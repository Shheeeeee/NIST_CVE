# Chemin local où vous souhaitez enregistrer le fichier téléchargé
$destinationPath = "C:\Users\r.uriol"

# Chemin distant du fichier que vous souhaitez télécharger
$remoteFilePath = "/home/ugop/NIST_CVE/Rapports/CERT - Bulletin_de_veille_20230727.pptx"


# Demander le mot de passe de l'utilisateur
$securePassword = Read-Host "Veuillez entrer le mot de passe pour l'utilisateur $username" -AsSecureString
$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))

# Adresse IP, nom d'utilisateur et mot de passe de la machine distante
$remoteHost = "10.30.69.16"
$username = "ugop"

# Chemin vers l'exécutable WinSCP (winscp.com ou winscp.exe)
$winscpPath = "C:\Program Files (x86)\WinSCP\WinSCP.exe"

# Commande pour télécharger le fichier via WinSCP
$winscpScript = @"
option batch on
option confirm off
open sftp://${username}:${password}@${remoteHost}/
get "$remoteFilePath" "$destinationPath"
exit
"@

# Enregistrez le script dans un fichier temporaire
$winscpScriptPath = "C:\Users\r.uriol\winscp_script.txt"
$winscpScript | Out-File -Encoding ASCII $winscpScriptPath

# Exécutez WinSCP avec le script
Start-Process $winscpPath -ArgumentList "/script=$winscpScriptPath"

# Supprimez le fichier temporaire du script
Remove-Item $winscpScriptPath