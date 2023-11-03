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

# Demander à l'utilisateur de fournir le nom de l'environnement Anaconda (ou utiliser "base" par défaut)
$condaEnvironment = Read-Host "Veuillez entrer le nom de l'environnement Anaconda (ou appuyez sur Entrée pour utiliser 'base')"

if ([string]::IsNullOrEmpty($condaEnvironment)) {
    $condaEnvironment = "base"
}

# Cloner les projets GitHub
foreach ($githubProject in $githubProjects) {
    Write-Host "Clonage du projet GitHub : $githubProject dans le répertoire courant"
    git clone $githubProject
}

# Installer les packages pip globalement dans l'environnement Anaconda spécifié
foreach ($pipPackage in $pipPackages) {
    Write-Host "Installation du package pip : $pipPackage dans l'environnement Anaconda '$condaEnvironment'"
    conda activate $condaEnvironment
    pip install $pipPackage
    conda deactivate
}

Write-Host "Toutes les opérations ont été effectuées avec succès."
