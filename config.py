class Config:
    WHITELIST = ['Notepad.exe', 'svchost.exe', 'conhost.exe',
                                'RuntimeBroker.exe',
                                'msedge.exe', 'backgroundTaskHost.exe',
                                'SearchProtocolHost.exe', 'WinStore.App.exe', 'WmiPrvSE.exe',
                                'WindowsPackageManagerServer.exe', 'AccountsControlHost.exe',
                                'WWAHost.exe', 'WindowsCamera.exe', 'devenv.exe',
                                'SystemSettings.exe', 'MoUsoCoreWorker.exe', 'PerfWatson2.exe',
                                'dllhost.exe', 'Microsoft.ServiceHub.Controller.exe',
                                'explorer.exe', 'ServiceHub.VSDetouredHost.exe',
                                'ServiceHub.SettingsHost.exe', 'ServiceHub.Host.dotnet.x64.exe',
                                'ServiceHub.Host.netfx.x86.exe', 'ubuntu.exe',
                                'ServiceHub.IndexingService.exe', 'vmcompute.exe', 'msteams.exe',
                                'mmc.exe', 'msedgewebview2.exe', 'Taskmgr.exe', 'OneDrive.exe',
                                'mspaint.exe', 'ScreenSketch.exe', 'Cortana.exe',
                                'Win32Bridge.Server.exe', 'Time.exe', 'StickyNotesStub.exe',
                                'SoundRec.exe', 'Microsoft.Notes.exe', 'VoiceRecorder.exe',
                                'SecHealthUI.exe', 'SecurityHealthHost.exe', 'sppsvc.exe',
                                'GameBar.exe', 'taskhsvc.exe', 'SearchFilterHost.exe',
                                'consent.exe', 'ctfmon.exe', 'WMIC.exe',
                                'VSSVC.exe', 'notepad++.exe']
    SAFE_GUARD_WHITELIST = ['notepad.exe', 'notepad++.exe'],
    SUSPECTED_RDNS = []
    SUSPECTED_RADDR = ['91.218.114.11', '91.218.114.4', '91.218.114.25', '91.218.114.32', '91.218.114.38',
                       '91.218.114.31', '91.218.114.26']
    DUMP_INTERVAL = 10
    SAFE_GUARD_FOLDER = 'C:\\Safe_Guard'
    SAFE_GUARD_MARK = 'Safe_Guard',
    GOOGLE_DRIVE_TARGET_FOLDER_ID = '',
    GOOGLE_DRIVE_CLIENT_SECRETS_JSON_FILE = '',
    DEBUG = False

    def __init__(self):
        pass
