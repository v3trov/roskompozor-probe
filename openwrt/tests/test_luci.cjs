const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const directory = path.resolve(__dirname, '../../luci-app-roskompozor-probe/files');
const source = fs.readFileSync(path.join(directory, 'roskompozor-probe.js'), 'utf8');
const key = 'rkp_' + 'a'.repeat(64);
const config = {server: 'https://roskompozor.ru', api_key: key, poll_interval: 10, request_timeout: 10, max_parallel_checks: 1, future_setting: 'preserve'};
const calls = [];
let rejectSave = false, running = false;
function E(tag, attrs, children) { return {tag, attrs, children, textContent: typeof children === 'string' ? children : ''}; }
class Map {
    constructor(data) {
        this.values = data.probe;
        this.options = {};
        this.data = {get: (configName, section) => { assert.equal(section, 'probe'); return this.values; }};
    }
    section() { return {option: (type, name) => this.options[name] = {}}; }
    render() { return Promise.resolve(E('form', {}, [])); }
    save() {
        for (const [name, option] of Object.entries(this.options))
            if (option.validate && option.validate('probe', this.values[name]) !== true)
                return Promise.reject(new Error('validation failed'));
        return Promise.resolve();
    }
}
const context = {
    view: {extend: value => value},
    form: {JSONMap: Map, NamedSection: {}, Value: {}, Flag: {}},
    fs: {
        read: async file => { assert.equal(file, '/etc/roskompozor-probe/config.json'); return JSON.stringify(config); },
        write: async (file, data, mode) => { calls.push(['write', file, JSON.parse(data), mode]); },
        exec: async (command, args) => {
            assert.equal(command, '/usr/libexec/roskompozor-probe-config');
            assert.equal(args.length, 1);
            calls.push(['command', args[0]]);
            if (args[0] === 'save' && rejectSave) return {code: 1, stderr: key};
            if (args[0] === 'restart') running = true;
            return {code: 0, stdout: args[0] === 'status' ? (running ? '1' : '0') : '0'};
        }
    },
    ui: {createHandlerFn: (self, fn) => fn.bind(self), addNotification: (...args) => calls.push(['notification', ...args])},
    URL, E, window: {location: {reload() {}}}, Promise, Object, Number, Error, JSON
};
const view = vm.runInNewContext('(function(){' + source + '\n})()', context);
(async () => {
    await view.render(await view.load());
    assert.equal(view.map.options.api_key.password, true);
    assert.equal(view.map.options.api_key.validate('probe', 'bad-key'), 'Ключ должен начинаться с rkp_ и содержать 64 шестнадцатеричных символа.');
    assert.notEqual(view.map.options.server.validate('probe', 'https://user:secret@example.com'), true);
    assert.notEqual(view.map.options.server.validate('probe', 'http://example.com'), true);
    calls.length = 0;
    Object.assign(view.map.values, {poll_interval: '15', request_timeout: '8.5', max_parallel_checks: '2', enabled: '1', server: 'https://roskompozor.ru/', api_connect_ip: '192.168.1.220'});
    await view.handleSaveApply();
    const write = calls.find(call => call[0] === 'write');
    assert.equal(write[1], '/etc/roskompozor-probe/config.pending');
    assert.equal(write[3], 384); // 0600
    assert.equal(write[2].future_setting, 'preserve');
    assert.equal(write[2].api_key, key);
    assert.equal(write[2].max_parallel_checks, 2);
    assert.equal(write[2].request_timeout, 8.5);
    assert.equal(write[2].server, 'https://roskompozor.ru');
    assert.equal(write[2].api_connect_ip, '192.168.1.220');
    assert.equal('enabled' in write[2], false);
    assert.deepEqual(calls.filter(call => call[0] === 'command').map(call => call[1]), ['save', 'enable', 'restart', 'status']);
    assert.equal(view.statusNode.textContent, 'Работает');
    calls.length = 0;
    rejectSave = true;
    await assert.rejects(view.handleSaveApply(), error => !error.message.includes(key));
    assert.equal(calls.some(call => call[1] === 'restart'), false);
    assert.equal(calls.some(call => call[0] === 'notification'), false);
    calls.length = 0;
    rejectSave = false;
    view.map.values.api_key = 'bad';
    await assert.rejects(view.handleSaveApply());
    assert.equal(calls.length, 0);
    const menu = JSON.parse(fs.readFileSync(path.join(directory, 'menu.json')));
    assert.equal(menu['admin/services/roskompozor-probe'].action.path, 'roskompozor-probe');
    const acl = JSON.parse(fs.readFileSync(path.join(directory, 'acl.json')))['luci-app-roskompozor-probe'];
    assert.deepEqual(Object.keys(acl.write.file).filter(file => !file.includes('roskompozor-probe-config')), ['/etc/roskompozor-probe/config.pending']);
    assert.equal(JSON.stringify(acl).includes('*'), false);
    console.log('LuCI: validation, secret field, atomic-save flow, restart, failure handling, menu and ACL passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
