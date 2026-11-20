//! The Android app's JNI boundary. Enrollment, authentication, authorization and
//! operation lifetime remain in the shared Rust Host; Java supplies Android APIs.
#![cfg(target_os = "android")]

use jni::{
    JNIEnv, JavaVM,
    objects::{GlobalRef, JClass, JObject, JString, JValue},
    sys::jstring,
};
use serde_json::{Value, json};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    ptr,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use styx_contracts::error::ErrorCategory;
use styx_runtime::{
    android::{self, RunStatus},
    enrollment::client::{self, ClientError, CredentialStore},
    host::android::AndroidPlatform as HostPlatform,
};
use tokio::{runtime::Runtime, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

struct BridgeError {
    code: &'static str,
    uncertain: bool,
}
impl BridgeError {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            uncertain: false,
        }
    }
    fn unknown(code: &'static str) -> Self {
        Self {
            code,
            uncertain: true,
        }
    }
    fn json(self) -> Value {
        json!({"ok":false,"error":{"code":self.code,"uncertain":self.uncertain}})
    }
}
impl From<ClientError> for BridgeError {
    fn from(error: ClientError) -> Self {
        Self {
            code: error.code,
            uncertain: error.uncertain,
        }
    }
}

/// One reference to the app's platform object; native worker threads attach to
/// the existing VM. JNI local strings are released after every callback.
struct JavaPlatform {
    vm: JavaVM,
    object: GlobalRef,
}
impl JavaPlatform {
    fn new(env: &JNIEnv<'_>, object: JObject<'_>) -> Result<Arc<Self>, BridgeError> {
        if object.is_null() {
            return Err(BridgeError::new("android_platform_missing"));
        }
        Ok(Arc::new(Self {
            vm: env
                .get_java_vm()
                .map_err(|_| BridgeError::new("android_vm_unavailable"))?,
            object: env
                .new_global_ref(object)
                .map_err(|_| BridgeError::new("android_platform_unavailable"))?,
        }))
    }

    fn call<T>(
        &self,
        callback: impl FnOnce(&mut JNIEnv<'_>) -> jni::errors::Result<T>,
    ) -> Result<T, BridgeError> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| BridgeError::new("android_thread_unavailable"))?;
        let result = env.with_local_frame(8, callback);
        if result.is_err() {
            // Java exception text may contain user data. Do not describe or log it.
            let _ = env.exception_clear();
        }
        result.map_err(|_| BridgeError::unknown("android_callback_failed"))
    }
}
impl CredentialStore for JavaPlatform {
    fn load(&self) -> Result<Option<Zeroizing<String>>, ClientError> {
        self.call(|env| {
            let value = env
                .call_method(
                    self.object.as_obj(),
                    "loadCredentials",
                    "()Ljava/lang/String;",
                    &[],
                )?
                .l()?;
            if value.is_null() {
                return Ok(None);
            }
            let text: String = env.get_string(&JString::from(value))?.into();
            Ok(Some(Zeroizing::new(text)))
        })
        .map_err(|_| ClientError::new("android_credentials_unavailable"))
    }

    fn save(&self, json: &str) -> Result<(), ClientError> {
        self.call(|env| {
            let value = env.new_string(json)?;
            env.call_method(
                self.object.as_obj(),
                "storeCredentials",
                "(Ljava/lang/String;)V",
                &[JValue::Object(value.as_ref())],
            )?;
            Ok(())
        })
        .map_err(|_| ClientError::new("android_credentials_write_failed"))
    }
}
impl HostPlatform for JavaPlatform {
    fn execute(&self, method: &str, args: Value) -> Result<Value, ErrorCategory> {
        let args = serde_json::to_string(&args).map_err(|_| ErrorCategory::InvalidRequest)?;
        let returned = self
            .call(|env| {
                let method = env.new_string(method)?;
                let args = env.new_string(args)?;
                let result = env
                    .call_method(
                        self.object.as_obj(),
                        "execute",
                        "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                        &[
                            JValue::Object(method.as_ref()),
                            JValue::Object(args.as_ref()),
                        ],
                    )?
                    .l()?;
                let text: String = env.get_string(&JString::from(result))?.into();
                Ok(text)
            })
            .map_err(|_| ErrorCategory::ResultUnknown)?;
        serde_json::from_str(&returned).map_err(|_| ErrorCategory::ResultUnknown)
    }
}

struct ActiveHost {
    environment_id: String,
    stop: CancellationToken,
    task: JoinHandle<Result<(), ErrorCategory>>,
}
struct HostState {
    runtime: Runtime,
    control: Mutex<()>,
    active: Mutex<Option<ActiveHost>>,
    status: Arc<Mutex<Value>>,
}
static HOST: OnceLock<HostState> = OnceLock::new();
fn host() -> &'static HostState {
    HOST.get_or_init(|| HostState {
        runtime: tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Android Host runtime initialization failed"),
        control: Mutex::new(()),
        active: Mutex::new(None),
        status: Arc::new(Mutex::new(json!({"ok":true,"state":"stopped"}))),
    })
}
fn public_status() -> Result<Value, BridgeError> {
    match HOST.get() {
        Some(host) => host
            .status
            .lock()
            .map(|value| value.clone())
            .map_err(|_| BridgeError::new("host_state_unavailable")),
        None => Ok(json!({"ok":true,"state":"stopped"})),
    }
}
fn read_string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Result<String, BridgeError> {
    env.get_string(value)
        .map(Into::into)
        .map_err(|_| BridgeError::new("invalid_arguments"))
}

/// Panics and pending Java exceptions must not escape the JNI boundary. All
/// response text is generated from closed error codes, never exception messages.
fn export<'local>(
    mut env: JNIEnv<'local>,
    action: impl FnOnce(&mut JNIEnv<'local>) -> Result<Value, BridgeError>,
) -> jstring {
    let response = match catch_unwind(AssertUnwindSafe(|| action(&mut env))) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => error.json(),
        Err(_) => BridgeError::unknown("native_host_failed").json(),
    };
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
    env.new_string(response.to_string())
        .map(|value| value.into_raw())
        .unwrap_or(ptr::null_mut())
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_styx_host_NativeHost_pair<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    gateway: JString<'local>,
    code: JString<'local>,
    label: JString<'local>,
    platform: JObject<'local>,
) -> jstring {
    export(env, |env| {
        let gateway = read_string(env, &gateway)?;
        let code = Zeroizing::new(read_string(env, &code)?);
        let label = read_string(env, &label)?;
        let platform = JavaPlatform::new(env, platform)?;
        let host = host();
        let _control = host
            .control
            .lock()
            .map_err(|_| BridgeError::new("host_state_unavailable"))?;
        if host
            .active
            .lock()
            .map_err(|_| BridgeError::new("host_state_unavailable"))?
            .as_ref()
            .is_some_and(|active| !active.task.is_finished())
        {
            return Err(BridgeError::new("host_already_running"));
        }
        let credentials =
            host.runtime
                .block_on(client::pair(platform.as_ref(), &gateway, &code, &label))?;
        let response =
            json!({"ok":true,"state":"paired","environment_id":credentials.device_id.as_str()});
        *host
            .status
            .lock()
            .map_err(|_| BridgeError::new("host_state_unavailable"))? = response.clone();
        Ok(response)
    })
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_styx_host_NativeHost_start<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    config: JString<'local>,
    platform: JObject<'local>,
) -> jstring {
    export(env, |env| {
        let config: Value = serde_json::from_str(&read_string(env, &config)?)
            .map_err(|_| BridgeError::new("invalid_arguments"))?;
        let files_dir = PathBuf::from(
            config
                .get("files_dir")
                .and_then(Value::as_str)
                .ok_or_else(|| BridgeError::new("android_files_directory_missing"))?,
        );
        let platform = JavaPlatform::new(env, platform)?;
        let host = host();
        let _control = host
            .control
            .lock()
            .map_err(|_| BridgeError::new("host_state_unavailable"))?;
        let mut active = host
            .active
            .lock()
            .map_err(|_| BridgeError::new("host_state_unavailable"))?;
        if let Some(current) = active
            .as_ref()
            .filter(|current| !current.task.is_finished())
        {
            return Ok(
                json!({"ok":true,"state":"running","environment_id":current.environment_id}),
            );
        }
        active.take();
        // resume() resolves any persisted pairing phase through the existing
        // read-only status path; it never repeats a join with an unknown outcome.
        let credentials = host.runtime.block_on(client::resume(platform.as_ref()))?;
        let environment_id = credentials.device_id.as_str().to_owned();
        *host
            .status
            .lock()
            .map_err(|_| BridgeError::new("host_state_unavailable"))? =
            json!({"ok":true,"state":"starting","environment_id":environment_id});
        let status = Arc::clone(&host.status);
        let finished_status = Arc::clone(&host.status);
        let report: Arc<dyn Fn(RunStatus) + Send + Sync> = Arc::new(move |state| {
            if let Ok(mut value) = status.lock() {
                if let Ok(mut next) = serde_json::to_value(state) {
                    next["ok"] = Value::Bool(true);
                    *value = next;
                }
            }
        });
        let stop = CancellationToken::new();
        let task_stop = stop.clone();
        let run_platform: Arc<dyn HostPlatform> = platform;
        let task = host.runtime.spawn(async move {
            let result =
                android::run(credentials, &files_dir, run_platform, task_stop, report).await;
            if let Err(category) = result {
                if let Ok(mut status) = finished_status.lock() {
                    if !matches!(
                        status.get("state").and_then(Value::as_str),
                        Some("revoked" | "failed")
                    ) {
                        status["state"] = json!("failed");
                        status["code"] = json!("android_host_failed");
                        status["error_category"] = json!(category);
                    }
                }
            }
            result
        });
        *active = Some(ActiveHost {
            environment_id: environment_id.clone(),
            stop,
            task,
        });
        Ok(json!({"ok":true,"state":"starting","environment_id":environment_id}))
    })
}

// Call only while holding the existing lifecycle control lock.
fn stop_active(host: &HostState) -> Result<(), BridgeError> {
    let mut slot = host
        .active
        .lock()
        .map_err(|_| BridgeError::new("host_state_unavailable"))?;
    let Some(active) = slot.as_mut() else {
        return Ok(());
    };
    active.stop.cancel();
    match host
        .runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(5), &mut active.task).await })
    {
        Ok(result) => {
            slot.take();
            let _ = result.map_err(|_| BridgeError::unknown("host_task_failed"))?;
            Ok(())
        }
        Err(_) => Err(BridgeError::unknown("host_stop_pending")),
    }
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_styx_host_NativeHost_stop(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    export(env, |_| {
        let Some(host) = HOST.get() else {
            return public_status();
        };
        let _control = host
            .control
            .lock()
            .map_err(|_| BridgeError::new("host_state_unavailable"))?;
        stop_active(host)?;
        public_status()
    })
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_styx_host_NativeHost_forget<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    platform: JObject<'local>,
) -> jstring {
    export(env, |env| {
        let platform = JavaPlatform::new(env, platform)?;
        let host = host();
        let _control = host
            .control
            .lock()
            .map_err(|_| BridgeError::new("host_state_unavailable"))?;
        // Local forgetting never races an active pairing or authenticated Host.
        // If stop is still pending, retain the existing protected credentials.
        stop_active(host)?;
        platform
            .call(|env| {
                env.call_method(platform.object.as_obj(), "forgetCredentials", "()V", &[])?;
                Ok(())
            })
            .map_err(|_| BridgeError::unknown("android_credentials_remove_failed"))?;
        let response = json!({"ok":true,"state":"stopped","code":"pairing_forgotten"});
        *host
            .status
            .lock()
            .map_err(|_| BridgeError::new("host_state_unavailable"))? = response.clone();
        Ok(response)
    })
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_styx_host_NativeHost_status(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    export(env, |_| public_status())
}
