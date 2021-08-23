import { readFileSync } from 'fs';
import path from 'path';
import { Buffer } from 'buffer';
import { DataItemCreateOptions } from '../ar-data-base';
import { bundleAndSignData, createData, DataItem } from '..';
import * as fs from 'fs';
import ArweaveSigner from '../signing/chains/arweave/ArweaveSigner';

const wallet0 = JSON.parse(
  readFileSync(path.join(__dirname, 'test_key0.json')).toString(),
);

describe('Creating and indexing a data item', function() {
  it('should create with all and get', async function() {
    const _d: DataItemCreateOptions = {
      data: 'tasty',
      target: 'pFwvlpz1x_nebBPxkK35NZm522XPnvUSveGf4Pz8y4A',
      anchor: 'Math.apt\'#]gng(36).substring(30)',
      tags: [{
        name: "testname",
        value: "testvalue"
      }]
    };

    const signer = new ArweaveSigner(wallet0);

    const d = await createData(_d, signer);
    await d.sign(signer);
    expect(Buffer.from(d.rawData).toString()).toBe('tasty');
    expect(d.owner).toBe(wallet0.n);
    expect(d.target).toBe('pFwvlpz1x_nebBPxkK35NZm522XPnvUSveGf4Pz8y4A');
    expect(d.anchor).toEqual('Math.apt\'#]gng(36).substring(30)');
    expect(d.tags).toEqual([{
      name: "testname",
      value: "testvalue"
    }]);
    expect(await DataItem.verify(d.getRaw(), { pk: wallet0.n })).toEqual(true);
  });

  it('should create with no target and get', async function() {
    const _d: DataItemCreateOptions = {
      data: 'tasty',
      anchor: 'Math.apt\'#]gng(36).substring(30)',
      tags: [{
        name: "testname",
        value: "testvalue"
      }]
    };

    const signer = new ArweaveSigner(wallet0);

    const d = await createData(_d, signer);
    await d.sign(signer);
    expect(Buffer.from(d.rawData).toString()).toBe('tasty');
    expect(d.owner).toBe(wallet0.n);
    expect(d.target).toBe('');
    expect(d.anchor).toEqual('Math.apt\'#]gng(36).substring(30)');
    expect(d.tags).toEqual([{
      name: "testname",
      value: "testvalue"
    }]);
    expect(await DataItem.verify(d.getRaw(), { pk: wallet0.n })).toEqual(true);
  });

  it('should create with no anchor and get', async function() {
    const _d: DataItemCreateOptions = {
      data: 'tasty',
      target: 'pFwvlpz1x_nebBPxkK35NZm522XPnvUSveGf4Pz8y4A',
      tags: [{
        name: "testname",
        value: "testvalue"
      }]
    };

    const signer = new ArweaveSigner(wallet0);

    const d = await createData(_d, signer);
    await d.sign(signer);
    expect(Buffer.from(d.rawData).toString()).toBe('tasty');
    expect(d.owner).toBe(wallet0.n);
    expect(d.target).toBe('pFwvlpz1x_nebBPxkK35NZm522XPnvUSveGf4Pz8y4A');
    expect(d.anchor).toEqual('');
    expect(d.tags).toEqual([{
      name: "testname",
      value: "testvalue"
    }]);
    expect(await DataItem.verify(d.getRaw(), { pk: wallet0.n })).toEqual(true);
  });

  it('should create with no target or anchor and get', async function() {
    const _d: DataItemCreateOptions = {
      data: 'tasty',
      tags: [{
        name: "testname",
        value: "testvalue"
      }]
    };

    const signer = new ArweaveSigner(wallet0);

    const d = await createData(_d, signer);
    await d.sign(signer);
    expect(Buffer.from(d.rawData).toString()).toBe('tasty');
    expect(d.owner).toBe(wallet0.n);
    expect(d.target).toBe('');
    expect(d.anchor).toEqual('');
    expect(d.tags).toEqual([{
      name: "testname",
      value: "testvalue"
    }]);
    expect(await DataItem.verify(d.getRaw(), { pk: wallet0.n })).toEqual(true);
  });


  it('Test Bundle', async function() {
    const signer = new ArweaveSigner(wallet0);
    const _dataItems: DataItemCreateOptions[] = [{
      data: 'tasty',
      target: 'pFwvlpz1x_nebBPxkK35NZm522XPnvUSveGf4Pz8y4A',
      anchor: 'Math.randomgng(36).substring(30)',
      tags: [{ name: 'x', value: 'y' }],
    }];

    const bundle = await bundleAndSignData(_dataItems, signer);
    const dataItems = bundle.items;

    expect(bundle.length).toEqual(1);
    expect(dataItems.length).toEqual(1);
    expect(Buffer.from(dataItems[0].rawData).toString()).toBe('tasty');
    expect(dataItems[0].owner).toBe(wallet0.n);
    expect(Buffer.from(dataItems[0].target).toString()).toBe('pFwvlpz1x_nebBPxkK35NZm522XPnvUSveGf4Pz8y4A');
    expect(dataItems[0].anchor).toEqual('Math.randomgng(36).substring(30)');
    expect(dataItems[0].tags).toEqual([{ name: 'x', value: 'y' }]);
    expect(await DataItem.verify(dataItems[0].getRaw())).toEqual(true);
  });

  it('Test bugs', async function() {
    const signer = new ArweaveSigner(wallet0);
    const bundle = await bundleAndSignData([
      { data: '1984' },
      { data: '4242' },
    ], signer);

    expect(bundle.get(1).rawData).toEqual(Buffer.from('4242'));
  });

  it('Test file verification', async function() {
    const signer = new ArweaveSigner(wallet0);
    const _d: DataItemCreateOptions = {
      data: 'tasty',
      anchor: 'Math.apt\'#]gng(36).substring(30)',
      tags: [{
        name: "test",
        value: "hbjhjh"
      }]
    };

    const d = await createData(_d, signer);
    await d.sign(signer);
    const binary = d.getRaw();
    fs.writeFileSync('test', binary);
    const fileBinary = fs.readFileSync('test');
    expect(fileBinary).toEqual(binary);
  });

  it('Test failed file verification', async function() {
    fs.writeFileSync('test', Buffer.from('hi'));
    const fileBinary = fs.readFileSync('test');
    expect(await DataItem.verify(fileBinary)).toEqual(false);
  });

  it('should verify', async function() {
    const signer = new ArweaveSigner(wallet0);
    const bundle = await bundleAndSignData([
      { data: '1984', tags: [{ name: "gdf", value: "gfgdf" }] },
      { data: '4242' },
    ], signer);

    expect(bundle.verify()).toEqual(true);
  });
});
