"""Persistent socket-only SDK worker. It cannot launch a Cua daemon."""
import asyncio,json,sys,os,stat
import cua_driver

async def main():
 socket=sys.argv[1]
 s=os.lstat(socket)
 if not stat.S_ISSOCK(s.st_mode) or s.st_uid!=os.geteuid(): raise RuntimeError('untrusted_socket')
 driver=cua_driver.CuaDriver.connect(socket)
 for line in sys.stdin:
  req=json.loads(line)
  try:
   if req['name']=='metadata':
    meta=await asyncio.wait_for(driver.metadata(),5)
    result={'driver_version':meta.driver_version,'contract_version':meta.contract_version,'pid':meta.pid,'embedded':meta.embedded,'host_bundle_id':meta.host_bundle_id}
   else:
    r=await asyncio.wait_for(driver.call_tool(req['name'],json.dumps(req.get('arguments',{}))),8)
    result=json.loads(r.raw_json)
   print(json.dumps({'id':req['id'],'result':result},ensure_ascii=False),flush=True)
  except Exception:
   print(json.dumps({'id':req['id'],'error':'driver_request_failed'}),flush=True)
 await driver.shutdown() # Connected clients do not own or stop the daemon.
asyncio.run(main())
