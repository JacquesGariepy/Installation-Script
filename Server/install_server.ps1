# Liste des projets GitHub à cloner
$githubProjects = @(
    "https://github.com/JacquesGariepy/Installation-Script.git",
    #"https://github.com/votre-utilisateur/votre-projet.git",
    # Ajoutez d'autres liens de projets GitHub ici
)

# Liste des packages pip à installer
$pipPackages = @(
    "apache-airflow[celery]==2.7.2 --constraint https://raw.githubusercontent.com/apache/airflow/constraints-2.7.2/constraints-3.8.txt",
    #"nom-du-package==version",
    # Ajoutez d'autres packages pip ici
)

# Demander à l'utilisateur de fournir le répertoire de destination
$destinationDirectory = Read-Host "Veuillez entrer le chemin complet du répertoire de destination pour cloner les projets GitHub :"

# Créer le répertoire s'il n'existe pas
if (-Not (Test-Path -Path $destinationDirectory -PathType Container)) {
    New-Item -Path $destinationDirectory -ItemType Directory
}

# Cloner les projets GitHub
foreach ($githubProject in $githubProjects) {
    Write-Host "Clonage du projet GitHub : $githubProject dans $destinationDirectory"
    git clone $githubProject $destinationDirectory
}

# Installer les packages pip
foreach ($pipPackage in $pipPackages) {
    Write-Host "Installation du package pip : $pipPackage"
    pip install $pipPackage
}

Write-Host "Toutes les opérations ont été effectuées avec succès."

# Question : Avez-vous des liens spécifiques de projets GitHub et de packages pip que vous souhaitez utiliser avec ce script ?
