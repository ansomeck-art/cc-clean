"""Product boundary for the retired HTTPS decryption feature.

No CA reads, subprocesses, sockets, proxy settings, client launch or trust edits.
The historical implementation remains available to isolated regression fixtures;
the macOS application does not import or bundle it.
"""

COUNTERS = ('checked', 'blocked', 'held', 'unattributed', 'tls_requests')
RETIRED_MESSAGE = 'HTTPS 正文解密已停用；请正常打开 Claude，使用只读网络与文件守护'


class ReadonlyTelemetryService:
    def __init__(self, data_dir=None):
        pass

    def status(self):
        return dict(owner='RegionGuard', state='retired', retired=True, running=False,
                    client_started=False, traffic_confirmed=False, session_id=None,
                    stats=dict.fromkeys(COUNTERS, 0), session_stats=dict.fromkeys(COUNTERS, 0),
                    error='', coverage='不检查或筛选 HTTPS 上传正文；已有证书信任未被修改')

    def refresh_trust(self, force=False):
        return False

    def stop(self):
        return self.status()

    def _retired(self):
        raise RuntimeError(RETIRED_MESSAGE)

    start = trust_certificate = launch_claude = _retired


def telemetry_filter_check(snapshot=None):
    return dict(id='telemetry_upload_filter', title='HTTPS 正文解密已停用',
                status='INFO', severity='low', observed='未启动解密代理，未检查上传正文',
                detail='当前版本仅使用只读文件与网络证据。不注入代理、安装证书或修改 Claude 启动参数；'
                       '不把 TUN 或全局模式视为全部流量已覆盖。已有证书信任未被更改。',
                fix_advice='', fix_cmd='')
