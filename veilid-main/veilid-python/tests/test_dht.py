# Routing context veilid tests

import veilid
import pytest
import asyncio
import json
import time
import os
from . import *
from .api import VeilidTestConnectionError, api_connector

##################################################################
BOGUS_KEY = veilid.TypedKey.from_value(
    veilid.CryptoKind.CRYPTO_KIND_VLD0, veilid.PublicKey.from_bytes(b'                                '))


@pytest.mark.asyncio
async def test_get_dht_value_unopened(api_connection: veilid.VeilidAPI):
    rc = await api_connection.new_routing_context()
    
    async with rc:
        with pytest.raises(veilid.VeilidAPIError):
            out = await rc.get_dht_value(BOGUS_KEY, veilid.ValueSubkey(0), False)


@pytest.mark.asyncio
async def test_open_dht_record_nonexistent_no_writer(api_connection: veilid.VeilidAPI):
    rc = await api_connection.new_routing_context()
    async with rc:
        with pytest.raises(veilid.VeilidAPIError):
            out = await rc.open_dht_record(BOGUS_KEY, None)


@pytest.mark.asyncio
async def test_close_dht_record_nonexistent(api_connection: veilid.VeilidAPI):
    rc = await api_connection.new_routing_context()
    async with rc:
        with pytest.raises(veilid.VeilidAPIError):
            await rc.close_dht_record(BOGUS_KEY)


@pytest.mark.asyncio
async def test_delete_dht_record_nonexistent(api_connection: veilid.VeilidAPI):
    rc = await api_connection.new_routing_context()
    async with rc:
        with pytest.raises(veilid.VeilidAPIError):
            await rc.delete_dht_record(BOGUS_KEY)


@pytest.mark.asyncio
async def test_create_delete_dht_record_simple(api_connection: veilid.VeilidAPI):
    rc = await api_connection.new_routing_context()
    async with rc:
        rec = await rc.create_dht_record(
            veilid.DHTSchema.dflt(1), veilid.CryptoKind.CRYPTO_KIND_VLD0
        )
        await rc.close_dht_record(rec.key)
        await rc.delete_dht_record(rec.key)


@pytest.mark.asyncio
async def test_get_dht_value_nonexistent(api_connection: veilid.VeilidAPI):
    rc = await api_connection.new_routing_context()
    async with rc:
        rec = await rc.create_dht_record(veilid.DHTSchema.dflt(1))
        assert await rc.get_dht_value(rec.key, 0, False) == None
        await rc.close_dht_record(rec.key)
        await rc.delete_dht_record(rec.key)


@pytest.mark.asyncio
async def test_set_get_dht_value(api_connection: veilid.VeilidAPI):
    rc = await api_connection.new_routing_context()
    async with rc:
        rec = await rc.create_dht_record(veilid.DHTSchema.dflt(2))

        vd = await rc.set_dht_value(rec.key, 0, b"BLAH BLAH BLAH")
        assert vd == None

        vd2 = await rc.get_dht_value(rec.key, 0, False)
        assert vd2 != None

        vd3 = await rc.get_dht_value(rec.key, 0, True)
        assert vd3 != None

        vd4 = await rc.get_dht_value(rec.key, 1, False)
        assert vd4 == None

        print("vd2: {}", vd2.__dict__)
        print("vd3: {}", vd3.__dict__)

        assert vd2 == vd3

        await rc.close_dht_record(rec.key)
        await rc.delete_dht_record(rec.key)


@pytest.mark.asyncio
async def test_open_writer_dht_value(api_connection: veilid.VeilidAPI):
    rc = await api_connection.new_routing_context()
    async with rc:
        rec = await rc.create_dht_record(veilid.DHTSchema.dflt(2))
        key = rec.key
        owner = rec.owner
        secret = rec.owner_secret
        print(f"key:{key}")

        cs = await api_connection.get_crypto_system(rec.key.kind())
        async with cs:
            assert await cs.validate_key_pair(owner, secret)
            other_keypair = await cs.generate_key_pair()

        va = b"Qwertyuiop Asdfghjkl Zxcvbnm"
        vb = b"1234567890"
        vc = b"!@#$%^&*()"

        # Test subkey writes
        vdtemp = await rc.set_dht_value(key, 1, va)
        assert vdtemp == None

        vdtemp = await rc.get_dht_value(key, 1, False)
        assert vdtemp.data == va
        assert vdtemp.seq == 0
        assert vdtemp.writer == owner

        vdtemp = await rc.get_dht_value(key, 0, False)
        assert vdtemp == None

        vdtemp = await rc.set_dht_value(key, 0, vb)
        assert vdtemp == None

        vdtemp = await rc.get_dht_value(key, 0, True)
        assert vdtemp.data == vb

        vdtemp = await rc.get_dht_value(key, 1, True)
        assert vdtemp.data == va

        # Equal value should not trigger sequence number update
        vdtemp = await rc.set_dht_value(key, 1, va)
        assert vdtemp == None

        # Different value should trigger sequence number update
        vdtemp = await rc.set_dht_value(key, 1, vb)
        assert vdtemp == None

        # Now that we initialized some subkeys
        # and verified they stored correctly
        # Delete things locally and reopen and see if we can write
        # with the same writer key

        await rc.close_dht_record(key)
        await rc.delete_dht_record(key)

        rec = await rc.open_dht_record(key, veilid.KeyPair.from_parts(owner, secret))
        assert rec != None
        assert rec.key == key
        assert rec.owner == owner
        assert rec.owner_secret == secret
        assert rec.schema.kind == veilid.DHTSchemaKind.DFLT
        assert rec.schema.o_cnt == 2

        # Verify subkey 1 can be set before it is get but newer is available online
        vdtemp = await rc.set_dht_value(key, 1, vc)
        assert vdtemp != None
        assert vdtemp.data == vb
        assert vdtemp.seq == 1
        assert vdtemp.writer == owner

        # Verify subkey 1 can be set a second time and it updates because seq is newer
        vdtemp = await rc.set_dht_value(key, 1, vc)
        assert vdtemp == None

        # Verify the network got the subkey update with a refresh check
        vdtemp = await rc.get_dht_value(key, 1, True)
        assert vdtemp != None
        assert vdtemp.data == vc
        assert vdtemp.seq == 2
        assert vdtemp.writer == owner

        # Delete things locally and reopen and see if we can write
        # with a different writer key (should fail)

        await rc.close_dht_record(key)
        await rc.delete_dht_record(key)

        rec = await rc.open_dht_record(key, other_keypair)
        assert rec != None
        assert rec.key == key
        assert rec.owner == owner
        assert rec.owner_secret == None
        assert rec.schema.kind == veilid.DHTSchemaKind.DFLT
        assert rec.schema.o_cnt == 2

        # Verify subkey 1 can NOT be set because we have the wrong writer
        with pytest.raises(veilid.VeilidAPIError):
            vdtemp = await rc.set_dht_value(key, 1, va)

        # Verify subkey 0 can NOT be set because we have the wrong writer
        with pytest.raises(veilid.VeilidAPIError):
            vdtemp = await rc.set_dht_value(key, 0, va)

        # Verify subkey 0 can be set because override with the right writer
        vdtemp = await rc.set_dht_value(key, 0, va, veilid.KeyPair.from_parts(owner, secret))
        assert vdtemp == None

        # Clean up
        await rc.close_dht_record(key)
        await rc.delete_dht_record(key)

@pytest.mark.asyncio
async def test_watch_dht_values():

    value_change_queue: asyncio.Queue[veilid.VeilidUpdate] = asyncio.Queue()

    async def value_change_update_callback(update: veilid.VeilidUpdate):
        if update.kind == veilid.VeilidUpdateKind.VALUE_CHANGE:
            await value_change_queue.put(update)

    try:
        api = await api_connector(value_change_update_callback)
    except VeilidTestConnectionError:
        pytest.skip("Unable to connect to veilid-server.")
        return

    # Make two routing contexts, one with and one without safety
    # So we can pretend to be a different node and get the watch updates
    # Normally they would not get sent if the set comes from the same target
    # as the watch's target
    rcWatch = await api.new_routing_context()
    
    rcSet = await (await api.new_routing_context()).with_safety(
        veilid.SafetySelection.unsafe(veilid.Sequencing.ENSURE_ORDERED)
    )
    async with rcWatch, rcSet:
        # Make a DHT record
        rec = await rcWatch.create_dht_record(veilid.DHTSchema.dflt(10))

        # Set some subkey we care about
        vd = await rcWatch.set_dht_value(rec.key, 3, b"BLAH BLAH BLAH")
        assert vd == None

        # Make a watch on that subkey
        ts = await rcWatch.watch_dht_values(rec.key, [], 0, 0xFFFFFFFF)
        assert ts != 0

        # Reopen without closing to change routing context and not lose watch
        rec = await rcSet.open_dht_record(rec.key, rec.owner_key_pair())
        
        # Now set the subkey and trigger an update
        vd = await rcSet.set_dht_value(rec.key, 3, b"BLAH")
        assert vd == None
        
        # Now we should NOT get an update because the update is the same as our local copy
        update = None
        try:
            update = await asyncio.wait_for(value_change_queue.get(), timeout=5)
        except asyncio.TimeoutError:
            pass
        assert update == None

        # Now set multiple subkeys and trigger an update
        vd = await asyncio.gather(*[rcSet.set_dht_value(rec.key, 3, b"BLAH BLAH"), rcSet.set_dht_value(rec.key, 4, b"BZORT")])
        assert vd == [None, None]

        # Wait for the update
        upd = await asyncio.wait_for(value_change_queue.get(), timeout=5)

        # Verify the update came back but we don't get a new value because the sequence number is the same
        assert upd.detail.key == rec.key
        assert upd.detail.count == 0xFFFFFFFD
        assert upd.detail.subkeys == [(3, 4)]
        assert upd.detail.value == None

        # Reopen without closing to change routing context and not lose watch
        rec = await rcWatch.open_dht_record(rec.key, rec.owner_key_pair())

        # Cancel some subkeys we don't care about
        still_active = await rcWatch.cancel_dht_watch(rec.key, [(0, 2)])
        assert still_active == True

        # Reopen without closing to change routing context and not lose watch
        rec = await rcSet.open_dht_record(rec.key, rec.owner_key_pair())

        # Now set multiple subkeys and trigger an update
        vd = await asyncio.gather(*[rcSet.set_dht_value(rec.key, 3, b"BLAH BLAH BLAH"), rcSet.set_dht_value(rec.key, 5, b"BZORT BZORT")])
        assert vd == [None, None]

        # Wait for the update
        upd = await asyncio.wait_for(value_change_queue.get(), timeout=5)

        # Verify the update came back but we don't get a new value because the sequence number is the same
        assert upd.detail.key == rec.key
        assert upd.detail.count == 0xFFFFFFFC
        assert upd.detail.subkeys == [(3, 3), (5, 5)]
        assert upd.detail.value == None

        # Reopen without closing to change routing context and not lose watch
        rec = await rcWatch.open_dht_record(rec.key, rec.owner_key_pair())

        # Now cancel the update
        still_active = await rcWatch.cancel_dht_watch(rec.key, [(3, 9)])
        assert still_active == False

        # Reopen without closing to change routing context and not lose watch
        rec = await rcSet.open_dht_record(rec.key, rec.owner_key_pair())

        # Now set multiple subkeys
        vd = await asyncio.gather(*[rcSet.set_dht_value(rec.key, 3, b"BLAH BLAH BLAH BLAH"), rcSet.set_dht_value(rec.key, 5, b"BZORT BZORT BZORT")])
        assert vd == [None, None]
        
        # Now we should NOT get an update
        update = None
        try:
            update = await asyncio.wait_for(value_change_queue.get(), timeout=5)
        except asyncio.TimeoutError:
            pass
        assert update == None

        # Clean up
        await rcSet.close_dht_record(rec.key)
        await rcSet.delete_dht_record(rec.key)

@pytest.mark.asyncio
async def test_inspect_dht_record(api_connection: veilid.VeilidAPI):
    rc = await api_connection.new_routing_context()
    async with rc:
        rec = await rc.create_dht_record(veilid.DHTSchema.dflt(2))

        vd = await rc.set_dht_value(rec.key, 0, b"BLAH BLAH BLAH")
        assert vd == None

        rr = await rc.inspect_dht_record(rec.key, [], veilid.DHTReportScope.LOCAL)
        print("rr: {}", rr.__dict__)
        assert rr.subkeys == [[0,1]]
        assert rr.local_seqs == [0, 0xFFFFFFFF]
        assert rr.network_seqs == []

        rr2 = await rc.inspect_dht_record(rec.key, [], veilid.DHTReportScope.SYNC_GET)
        print("rr2: {}", rr2.__dict__)
        assert rr2.subkeys == [[0,1]]
        assert rr2.local_seqs == [0, 0xFFFFFFFF]
        assert rr2.network_seqs == [0, 0xFFFFFFFF]

        await rc.close_dht_record(rec.key)
        await rc.delete_dht_record(rec.key)

@pytest.mark.skipif(os.getenv("INTEGRATION") != "1", reason="integration test requires two servers running")
@pytest.mark.asyncio
async def test_dht_integration_writer_reader():
    
    async def null_update_callback(update: veilid.VeilidUpdate):
        pass    

    try:
        api0 = await api_connector(null_update_callback, 0)
    except VeilidTestConnectionError:
        pytest.skip("Unable to connect to veilid-server 0.")
        return

    try:
        api1 = await api_connector(null_update_callback, 1)
    except VeilidTestConnectionError:
        pytest.skip("Unable to connect to veilid-server 1.")
        return

    async with api0, api1:
        # purge local and remote record stores to ensure we start fresh
        await api0.debug("record purge local")
        await api0.debug("record purge remote")
        await api1.debug("record purge local")
        await api1.debug("record purge remote")

        # make routing contexts
        rc0 = await api0.new_routing_context()
        rc1 = await api1.new_routing_context()
        async with rc0, rc1:

            COUNT = 100
            TEST_DATA = b"test data"

            # write dht records on server 0
            records = []
            schema = veilid.DHTSchema.dflt(1)
            print(f'writing {COUNT} records')
            for n in range(COUNT):
                desc = await rc0.create_dht_record(schema)
                records.append(desc)

                await rc0.set_dht_value(desc.key, 0, TEST_DATA)

                print(f'  {n}')
            
            print(f'syncing records to the network')
            for desc0 in records:
                while True:
                    rr = await rc0.inspect_dht_record(desc0.key, [])
                    if len(rr.offline_subkeys) == 0:
                        await rc0.close_dht_record(desc0.key)
                        break
                    time.sleep(0.1)

            # read dht records on server 1
            print(f'reading {COUNT} records')
            n=0
            for desc0 in records:
                desc1 = await rc1.open_dht_record(desc0.key)
                vd1 = await rc1.get_dht_value(desc1.key, 0)
                assert vd1.data == TEST_DATA
                await rc1.close_dht_record(desc1.key)
                
                print(f'  {n}')
                n+=1
                
@pytest.mark.asyncio
async def test_dht_write_read_local():
    
    async def null_update_callback(update: veilid.VeilidUpdate):
        pass    

    try:
        api0 = await api_connector(null_update_callback, 0)
    except VeilidTestConnectionError:
        pytest.skip("Unable to connect to veilid-server 0.")
        return

    async with api0:
        # purge local and remote record stores to ensure we start fresh
        await api0.debug("record purge local")
        await api0.debug("record purge remote")
        
        # make routing contexts
        rc0 = await api0.new_routing_context()
        async with rc0:

            COUNT = 500
            TEST_DATA = b"ABCD"*1024
            TEST_DATA2 = b"ABCD"*4096

            # write dht records on server 0
            records = []
            schema = veilid.DHTSchema.dflt(2)
            print(f'writing {COUNT} records')
            for n in range(COUNT):
                desc = await rc0.create_dht_record(schema)
                records.append(desc)

                await rc0.set_dht_value(desc.key, 0, TEST_DATA)
                await rc0.set_dht_value(desc.key, 1, TEST_DATA2)

                print(f'  {n}')
            
            print(f'syncing records to the network')
            for desc0 in records:
                while True:
                    rr = await rc0.inspect_dht_record(desc0.key, [])
                    if len(rr.offline_subkeys) == 0:
                        await rc0.close_dht_record(desc0.key)
                        break
                    time.sleep(0.1)

            # read dht records on server 0
            print(f'reading {COUNT} records')
            n=0
            for desc0 in records:
                desc1 = await rc0.open_dht_record(desc0.key)
                
                vd0 = await rc0.get_dht_value(desc1.key, 0)
                assert vd0.data == TEST_DATA
                
                vd1 = await rc0.get_dht_value(desc1.key, 1)
                assert vd1.data == TEST_DATA2
                await rc0.close_dht_record(desc1.key)
                
                print(f'  {n}')
                n+=1
                
            