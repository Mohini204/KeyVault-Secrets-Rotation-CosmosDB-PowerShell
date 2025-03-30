param($eventGridEvent, $TriggerMetadata)

function RegenerateCredential($credentialId, $providerAddress){
    Write-Host "Regenerating credential. Id: $credentialId Resource Id: $providerAddress"
    
    $cosmosDbAccountName = ($providerAddress -split '/')[8]
    $resourceGroupName = ($providerAddress -split '/')[4]
    
    #Regenerate read-only key
    $keyType = $credentialId + "ReadonlyMasterKey"

    $operationResult = New-AzCosmosDBAccountKey -ResourceGroupName $resourceGroupName -Name $cosmosDbAccountName -KeyKind $credentialId.ToLower()
    $dBKeys = Get-AzCosmosDBAccountKey -ResourceGroupName $resourceGroupName -Name $cosmosDbAccountName -Type "ReadOnlyKeys"

    $newCredentialValue = $dBKeys.Item($keyType)

    return $newCredentialValue
}

function GetAlternateCredentialId($credentialId){
    $validCredentialIds = "Primary", "Secondary"
    
    If($credentialId -notin $validCredentialIds){
        throw "Invalid credential id: $keyId. Credential id must be one of following:$validCredentialIds"
    }
    If($credentialId -eq "Primary"){
        return "Secondary"
    }
    Else{
        return "Primary"
    }
}

function AddSecretToKeyVault($keyVaultName,$secretName,$secretvalue,$exprityDate,$tags){
    
     Set-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName -SecretValue $secretvalue -Tag $tags -Expires $expiryDate

}

function RoatateSecret($keyVaultName,$secretName,$secretVersion){
    #Retrieve Secret
    $secret = (Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName)
    Write-Host "Secret Retrieved"
    
    If($secret.Version -ne $secretVersion){
        #if current version is different than one retrived in event
        Write-Host "Secret version is already rotated"
        return 
    }

    #Retrieve Secret Info
    $validityPeriodDays = $secret.Tags["ValidityPeriodDays"]
    $credentialId=  $secret.Tags["CredentialId"]
    $providerAddress = $secret.Tags["ProviderAddress"]
    
    Write-Host "Secret Info Retrieved"
    Write-Host "Validity Period: $validityPeriodDays"
    Write-Host "Credential Id: $credentialId"
    Write-Host "Provider Address: $providerAddress"

    #Get Credential Id to rotate - alternate credential
    $alternateCredentialId = GetAlternateCredentialId $credentialId
    Write-Host "Alternate credential id: $alternateCredentialId"

    #Regenerate alternate access credential in provider
    $newCredentialValue = (RegenerateCredential $alternateCredentialId $providerAddress)
    Write-Host "Credential regenerated. Credential Id: $alternateCredentialId Resource Id: $providerAddress"

    #Add new credential to Key Vault
    $newSecretVersionTags = @{}
    $newSecretVersionTags.ValidityPeriodDays = $validityPeriodDays
    $newSecretVersionTags.CredentialId=$alternateCredentialId
    $newSecretVersionTags.ProviderAddress = $providerAddress

    $expiryDate = (Get-Date).AddDays([int]$validityPeriodDays).ToUniversalTime()
    $secretvalue = ConvertTo-SecureString "$newCredentialValue" -AsPlainText -Force
    AddSecretToKeyVault $keyVaultName $secretName $secretvalue $expiryDate $newSecretVersionTags

    Write-Host "New credential added to Key Vault. Secret Name: $secretName"
}
$ErrorActionPreference = "Stop"
# Make sure to pass hashtables to Out-String so they're logged correctly
$eventGridEvent | ConvertTo-Json | Write-Host

$secretName = $eventGridEvent.subject
$secretVersion = $eventGridEvent.data.Version
$keyVaultName = $eventGridEvent.data.VaultName

Write-Host "Key Vault Name: $keyVaultName"
Write-Host "Secret Name: $secretName"
Write-Host "Secret Version: $secretVersion"

#Rotate secret
Write-Host "Rotation started."
RoatateSecret $keyVaultName $secretName $secretVersion
Write-Host "Secret Rotated Successfully"

