'use strict';
'require view';
'require form';
'require fs';
'require ui';

var configPath = '/etc/roskompozor-probe/config.json';
var pendingPath = '/etc/roskompozor-probe/config.pending';
var helper = '/usr/libexec/roskompozor-probe-config';

function command(action) {
    return fs.exec(helper, [action]).then(function(reply) {
        if (reply.code !== 0)
            throw new Error('Операция не выполнена: ' + action);
        return (reply.stdout || '').trim();
    });
}

return view.extend({
    load: function() {
        return Promise.all([fs.read(configPath), command('status'), command('enabled')]);
    },

    render: function(data) {
        var config;
        try { config = JSON.parse(data[0]); }
        catch (error) { throw new Error('Не удалось прочитать конфигурацию Probe. Проверьте config.json.'); }
        if (!config || typeof config !== 'object' || Array.isArray(config))
            throw new Error('Неверный формат конфигурации Probe.');
        this.original = config;
        this.enabled = data[2] === '1';
        var m = this.map = new form.JSONMap({probe: Object.assign({}, config, {enabled: this.enabled ? '1' : '0'})},
            'Roskompozor Probe', 'Лёгкий узел сетевой диагностики. Для этого роутера нужен отдельный API-ключ из админки Roskompozor.');
        var s = m.section(form.NamedSection, 'probe', 'probe', 'Настройки');
        s.addremove = false;
        var o = s.option(form.Value, 'api_key', 'API-ключ');
        o.password = true;
        o.rmempty = false;
        o.placeholder = 'rkp_…';
        o.validate = function(section, value) {
            return /^rkp_[a-fA-F0-9]{64}$/.test(value) ? true : 'Ключ должен начинаться с rkp_ и содержать 64 шестнадцатеричных символа.';
        };
        o = s.option(form.Value, 'api_connect_ip', 'IP для подключения к API');
        o.datatype = 'ipaddr';
        o.rmempty = true;
        o.description = 'Необязательно. Если сервер находится за этим роутером, укажите его локальный IP. Имя и TLS-сертификат проверяются по адресу сервера; проверки целей используют обычный DNS.';
        o = s.option(form.Value, 'poll_interval', 'Интервал опроса, секунд');
        o.datatype = 'and(uinteger,range(15,3600))';
        o.rmempty = false;
        o = s.option(form.Value, 'request_timeout', 'Таймаут API, секунд');
        o.datatype = 'range(2,60)';
        o.rmempty = false;
        o = s.option(form.Flag, 'enabled', 'Запускать при включении роутера');
        o.rmempty = false;

        var self = this;
        this.statusNode = E('strong', {}, data[1] === '1' ? 'Работает' : 'Остановлена');
        function actionButton(label, action) {
            return E('button', {class: 'cbi-button cbi-button-action', type: 'button', click: ui.createHandlerFn(self, function() {
                return command(action).then(function() { return self.refreshStatus(); });
            })}, label);
        }
        return m.render().then(function(node) {
            return E('div', {}, [
                E('div', {class: 'cbi-section'}, [E('p', {}, ['Служба: ', self.statusNode]),
                    E('div', {class: 'right'}, [actionButton('Запустить', 'start'), ' ', actionButton('Перезапустить', 'restart'), ' ', actionButton('Остановить', 'stop')])]),
                node,
                E('p', {}, '«Работает» означает, что процесс запущен. Получение заданий, отправка результатов и ошибки API доступны в системном журнале. «Сохранить и применить» перезапускает службу.')
            ]);
        });
    },

    refreshStatus: function() {
        var self = this;
        return command('status').then(function(status) {
            self.statusNode.textContent = status === '1' ? 'Работает' : 'Остановлена';
        });
    },

    handleSave: function() {
        var self = this;
        return this.map.save().then(function() {
            var values = self.map.data.get('json', 'probe');
            var config = Object.assign({}, self.original, {
                api_key: values.api_key,
                api_connect_ip: values.api_connect_ip || '',
                poll_interval: Number(values.poll_interval),
                request_timeout: Number(values.request_timeout),
                max_parallel_checks: 1
            });
            delete config.server;
            return fs.write(pendingPath, JSON.stringify(config, null, 2) + '\n', 384)
                .then(function() { return command('save'); })
                .then(function() { return command(values.enabled === '1' ? 'enable' : 'disable'); })
                .then(function() { self.original = config; });
        });
    },

    handleSaveApply: function() {
        var self = this;
        return this.handleSave().then(function() { return command('restart'); })
            .then(function() { return self.refreshStatus(); })
            .then(function() { ui.addNotification(null, E('p', {}, 'Настройки Probe сохранены и применены.'), 'info'); });
    },

    handleReset: function() { window.location.reload(); }
});
