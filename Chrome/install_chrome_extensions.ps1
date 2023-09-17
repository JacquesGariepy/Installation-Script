# Define a function to install Chrome extensions
function Install-ChromeExtension {
    param (
        [string]$extensionName,
        [string]$extensionID
    )

    Write-Host "Installing Chrome extension - $extensionName" -ForegroundColor Yellow
    $regPath = "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Google\Chrome\Extensions\$extensionID"
    $updateURL = "https://clients2.google.com/service/update2/crx"
    reg add $regPath /v update_url /t REG_SZ /d $updateURL /f
}

# List of extensions to install
$extensions = @{
    "Githunt" = "khpcnaokfebphakjgdgpinmglconplhp";
    "Angular DevTools" = "ienfalfjdbdpebioblfackkekamfmbnh";
    "WhatFont" = "jabopobgcpjmedljpbcaablpmlmfcogm";
    "colorpick eyedropper" = "ohcpnigalekghcmgcdcenkpelffpdolg";
    "window resizer" = "kkelicaakdanhinjdeammmilcgefonfh";
    "browserstack" = "nkihdmlheodkdfojglpcjjmioefjahjb";
    "CSSViewer" = "ggfgijbpiheegefliciemofobhmofgce";
    "Clear Cache" = "cppjkneekbjaeellbfkmgnhonkkjfpdn";
    "HTML Validator" = "mpbelhhnfhfjnaehkcnnaknldmnocglk";
    "JSON Viewer" = "gbmdgpbipfallnflgajpaliibnhdgobh";
    "AIPRM" = "ojnbohmppadfgpejeebfnmnknjdlckgj";
    "ChatGPT for Google" = "jgjaeacdkonaoafenlfkkkmbaopkbilf";
    "Google Traduction" = "aapbdbdomjkkjkaonfhkkikfgjllcleb";
    "ReaderGPT" = "ohgodjgnfedgikkgcjdkomkadbfedcjd";
    "WebChatGPT" = "lpfemeioodjbpieminkklglpmhlngfcn";
    "Superpower ChatGPT" = "amhmeenmapldpjdedekalnfifgnpfnkc";
    "HARPA AI" = "eanggfilgoajaocelnaflolkadkeghjp";
    "ChatGPT LINER" = "bmhcbmnbenmcecpmpepghooflbehcack";
    "AI Prompt Genius" = "jjdnakkfjnnbbckhifcfchagnpofjffo";
    # "" = "";
}

# Install each extension
foreach ($extension in $extensions.GetEnumerator()) {
    Install-ChromeExtension -extensionName $extension.Name -extensionID $extension.Value
}
