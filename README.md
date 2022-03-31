# Script powershell d'installation d'un nouveau poste
Installation des applications et des extensions pour Visual Studio 2022, VSCode et Chrome

## Config Windows : 
- Dans Options des dossiers selectionner "Afficher les fichiers, dossier et lecteurs cachés" et décocher "Masquer les extensions des fichiers dont le type est connu"
- Activer le mode developpeur windows : https://docs.microsoft.com/fr-fr/windows/apps/get-started/enable-your-device-for-development

- S'assurer que l'installateur d'applications (winget) est présent sur le poste : https://www.microsoft.com/fr-ca/p/app-installer/9nblggh4nns1?rtc=1#activetab=pivot:overviewtab

## Installation des scripts 
- Ouvrir "powershell ise" en mode admin. Lancer le script  "install.ps1".
	- Avant chaque section d'installation, veuillez lire la section apporpriée de ce readme.

### Installation des applications Windows 
- Si vous désirez ajouter des applications, il suffit de copier la commande winget du composant dans "Applications\install_applications.ps1". La commande peut être trouvée ici https://winget.run/
	- Pour les options de winget https://docs.microsoft.com/en-us/windows/package-manager/winget/
	
### Installation des extensions VSCode. 
- Dans VSCode -> menu File -> Preferences -> Settings -> Application -> Proxy : décoché "proxyStrictSSL" (mettre à false)
- Si vous désirez ajouter des extensions, il suffit de copier le nom du composant, dans la liste "AdditionalExtensions" du script "VS Code\install_vscode_extensions.ps1". 
	  Exemple d'ajout d'un extension dans le script : [string[]]$AdditionalExtensions = @("aaron-bond.better-comments","Angular.ng-template",...

### Installation des extensions Visual Studio 2022. 
- Si vous désirez ajouter des extensions, il suffit de copier le nom du composant dans le script "VisualStudio2022\install_visualstudio_extensions.ps1". Le nom du composant est trouvé dans l'url du Visual Studio Marketplace, après le paramêtre "itemName=". Ex.: VisualStudioPlatformTeam.ProductivityPowerPack2022 dans "https://marketplace.visualstudio.com/items?itemName=VisualStudioPlatformTeam.ProductivityPowerPack2022" 
	 exemple d'ajout d'un extension dans le script & $DownloadAndInstall -PackageName "SteveCadwallader.CodeMaidVS2022"
	
- Pour ajouter des packages nuget à installer, utiliser interface de ligne de commande .NET et ajouter la commande à la fin du script "VisualStudio2022\install_visualstudio_extensions.ps1". Ex.: dotnet tool install --global Microsoft.Tye --version 0.11.0-alpha.22111.1
	- Pour les options "dotnet tool install" https://docs.microsoft.com/en-us/dotnet/core/tools/dotnet-tool-install

### Installation d'extensions Chrome. 
- Après installations, vous devez activer les extensions dans l'onglet Extension de Chrome "chrome://extensions/"
- Si vous désirez ajouter des extensions, il suffit de copier l'id du composant dans le script "Chrome\install_chrome_extensions.ps1". L'id du composant est le dernier paramêtre de l'url de l'extension dans le WebStore de Chrome :ex.: "ienfalfjdbdpebioblfackkekamfmbnh" dans https://chrome.google.com/webstore/detail/angular-devtools/ienfalfjdbdpebioblfackkekamfmbnh

## Installation manuel
- Si une erreur survient lors de l'installation de l'extension winscp pour Visual Studio 2022, car le package provient de sourceforge et la source peut-être bloqué par votre organisation, installer manuellement https://winscp.net/eng/download.php

- Installation de WixToolset pour Visual Studio 2022 : https://wixtoolset.org/releases/

- Suite d'outils système SysinternalsSuite : https://download.sysinternals.com/files/SysinternalsSuite.zip
	
### Installation d'extensions non disponible pour Visual Studio 2022. Ajouter lorsque disponible
https://marketplace.visualstudio.com/items?itemName=ProBITools.MicrosoftAnalysisServicesModelingProjects
