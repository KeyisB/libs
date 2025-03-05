from KeyisBClient import AsyncClient, ProtocolsManager
import asyncio

import time

Client = AsyncClient()


async def main():
    #res = await Client.request('GET', 'https://dns.mmbproject.com:50000/servers?d=auth.gw')
    #print(res.status_code, res.json())
    time1 = time.time()
    print(time1)
    for i in range(25):

        res = await Client.request('GET', 'mmbp://updater.gw/apps/info2')
        print(res.status_code, end=' | ')

        #data = {}
        #data['username'] = 'qw2'
        #data['password'] = '12'
    
        
        #res = await Client.request('POST', 'mmbps://auth.gw/login', data=data)
        #print(res.status_code)
    time2 = time.time()
    print(time2 - time1)
    







asyncio.run(main())













