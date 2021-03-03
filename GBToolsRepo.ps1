$repo = @{}
$batchlist = @{}

$repo.add("mpc", @{
    installer = "\\GBEUKFILESERVER\Software$\Deploy\CCTV Players\Media Player Classic\MPC-HC.1.9.8.x64.exe"
    output = "\c$\Program Files\MPC-HC"
    uninstaller = "C:\Program Files\MPC-HC\unins000.exe"
    name = "Media Player Classic"
})

$repo.add("apowersoft", @{
    installer = "\\GBEUKFILESERVER\Software$\Deploy\APowersoft\screen-recorder-pro2.4.1.3.exe"
    output = "\c$\Program Files (x86)\Apowersoft"
    name = "Apowersoft"
})

$repo.add("autohotkey", @{
    installer = "\\GBEUKFILESERVER\Software$\Deploy\AutoHotkey\AutoHotkey_1.1.33.00_setup.exe"
    output = "\c$\Program Files\AutoHotkey"
    name = "AutoHotKey"
})

$repo.add("pdf24", @{
    installer = "\\GBEUKFILESERVER\Software$\Deploy\PDF24\pdf24-creator-9.2.2.exe"
    output = "\c$\Program Files (x86)\PDF24"
    name = "PDF24"
})

$repo.add("vsplayer", @{
    installer = "\\GBEUKFILESERVER\Software$\Deploy\CCTV Players\VSPlayer\VSPlayerV7.2.0.exe"
    output = "\c$\Program Files (x86)\VSPlayer"
    name = "VSPlayer"
})

$repo.add("notepad++", @{
    installer = "\\GBEUKFILESERVER\Software$\Deploy\notepad++\npp.7.9.2.Installer.exe"
    output = "\c$\Program Files (x86)\Notepad++"
    name = "Notepad++"
})

$repo.add("filezilla", @{
    installer = "\\GBEUKFILESERVER\Software$\Deploy\filezilla\FileZilla_3.45.1_win64_sponsored-setup(1).exe"
    output = "\c$\ProgramData\Microsoft\Windows\Start Menu\Programs\FileZilla FTP Client"
    name = "FileZilla"
})

$repo.add("webex-ptools", @{
    installer = "\\GBEUKFILESERVER\Software$\Deploy\Webex Productivity Tools\ptools.msi"
    output = "\c$\Program Files (x86)\WebEx\Productivity Tools"
    name = "Webex Productivity Tools"
}) 

$batchlist.add("strata", @("mpc", "apowersoft", "autohotkey", "pdf24"))