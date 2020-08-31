$clientId = "<put your client id here>"
$clientSecret = "<put your client secret here>"
$redirectUri = "http://localhost/oauth2callback"
$refreshToken = "<put your refreshtoken here>"
 
#Initialize default properties
$success = $False;
$p = $person | ConvertFrom-Json
$auditMessage = "Account for person " + $p.DisplayName + " not created successfully";
 
$defaultPassword = [System.Web.Security.Membership]::GeneratePassword(10, 0);
$defaultDomain = "yourdomain.com";

#Primary Email Generation
function get_username {
[cmdletbinding()]
Param (
[string]$firstName,
[string]$lastName,
[string]$domain,
[int]$Iteration
   ) 
    Process 
    {
        $suffix = "";
        if($Iteration -gt 0) { $suffix = ("00$($Iteration+1)").substring(1,2); };
        
        $temp_fn = $firstName;
        $temp_ln = $lastName;
        $temp_username = $temp_fn + "." + $temp_ln;
        
        $result = $temp_username + $suffix + $domain;
        $result = $result.toLower();
        @($result);
    }
}

$username = get_username -firstName $p.Name.NickName -lastName $p.Name.FamilyName -domain $defaultDomain -Iteration 0;

#Change mapping here
#For all of the supported attributes please check https://developers.google.com/admin-sdk/directory/v1/guides/manage-users
$account = [PSCustomObject]@{
    primaryEmail = $username
    name = @{
                givenName = $p.Name.NickName
                familyName = $p.Name.FamilyName
                fullName = ($p.Name.NickName + " " + $p.Name.FamilyName)
            }
    externalIds =  @(@{
                        value = $p.ExternalId
                        type = "organization";
                    })
    organizations = @(@{
                        title = ($p.primaryContract.Title.name)
                        #department = ($p.primaryContract.custom.TeamDesc)
                        #costCenter = ($p.primaryContract.costCenter.ExternalID)
                    })
    suspended = $True
}
 
#Check if account exists (externalId), else create
    $correlationResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users?customer=my_customer&query=externalId=$($p.ExternalId)&projection=FULL" -Method GET -Headers $authorization -Verbose:$false;
    
    if($correlationResponse.users.count -gt 0)
    {
        Write-Verbose -Message "Existing Account found" -Verbose
        $account.suspended = $False;
        
        $aRef = $correlationResponse.users[0].id;
        $body = $account | ConvertTo-Json -Depth 10
        Write-Verbose -Verbose ( $account | ConvertTo-Json -Depth 10);
        if(-Not($dryRun -eq $True)){
           $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users/$aRef" -Method PUT -Headers $authorization -Body $body -Verbose:$false
        }
    }
    else
    {
        $Iterator = 0;
        while($true)
        {
            #Check if username taken
            $usernameResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users?customer=my_customer&query=Email=$($account.primaryEmail)&projection=FULL" -Method GET -Headers $authorization -Verbose:$false

            if($usernameResponse.users.count -gt 0)
            {
                #Iterate
                Write-Verbose -Verbose "$($account.primaryEmail) already in use, iterating)"
                $Iterator++;
                $account.primaryEmail = get_username -firstName $p.Name.NickName -lastName $p.Name.FamilyName -domain $defaultDomain -Iteration $Iterator;
            }
            else
            {
                #Username available
                break;
            }
        }
        
        #Safe measure, set password on create only
        $account.password = $defaultPassword;
        
        if(-Not($dryRun -eq $True)){
           $body = $account | ConvertTo-Json -Depth 10
           $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users/$aRef" -Method POST -Headers $authorization -Body $body -Verbose:$false
           $aRef = $response.id
        }
    }
    $success = $True;
    $auditMessage = " successfully"; 
}catch{
    if(-Not($_.Exception.Response -eq $null)){
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $errResponse = $reader.ReadToEnd();
        $auditMessage = " : ${errResponse}";
    }else {
        $auditMessage = " $($_) : General error";
    } 
}
 
#build up result
$result = [PSCustomObject]@{
    Success= $success;
    AccountReference= $aRef;
    AuditDetails=$auditMessage;
    Account= $account;
};
  
Write-Output $result | ConvertTo-Json -Depth 10;
