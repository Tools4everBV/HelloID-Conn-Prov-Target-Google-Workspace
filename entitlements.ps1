# Get Google Entitlements (Groups & Licenses)
#region Initialize default properties
$config = ConvertFrom-Json $configuration
$gsuiteGroups = [System.Collections.Generic.List[object]]::new()
#endregion Initialize default properties

#region Support Functions
function Get-GoogleAccessToken() {
    ### exchange the refresh token for an access token
    $requestUri = "https://www.googleapis.com/oauth2/v4/token"

    $refreshTokenParams = @{
            client_id=$config.clientId;
            client_secret=$config.clientSecret;
            redirect_uri=$config.redirectUri;
            refresh_token=$config.refreshToken;
            grant_type="refresh_token"; # Fixed value
    };
    $response = Invoke-RestMethod -Method Post -Uri $requestUri -Body $refreshTokenParams -Verbose:$false
    $accessToken = $response.access_token

    #Add the authorization header to the request
    $authorization = [ordered]@{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
    $authorization
}
#endregion Support Functions

#region Execute
# Get Google Groups
try {
	#Add the authorization header to the request
	$authorization = Get-GoogleAccessToken


	$parameters = @{
		customer = "my_customer"
	}

	do {
		$splat = @{
			Uri = "https://www.googleapis.com/admin/directory/v1/groups"
			Body = $parameters
			Method = 'GET'
			Headers = $authorization
		}
		$response = Invoke-RestMethod @splat
		$parameters['pageToken'] = $response.nextPageToken;
		$gsuiteGroups.AddRange($response.groups);
	} while ($null -ne $parameters['pageToken'])
}catch{
    Write-Error $_
}

Write-Information "Total Groups $($gsuiteGroups.count)";
#endregion Execute


#region Build up result
#Return Groups
foreach($group in $gsuiteGroups)
{
	$row = @{
		DisplayName = $group.name;
		Identification = @{
			Id = $group.id;
			DisplayName = $group.name;
			Type = "Group";
		}
	};
	Write-Output ($row | ConvertTo-Json -Depth 10)
}

#Return Licensing
$licensing = '[{"DisplayName":"Google Workspace Business Starter","Identification":{"ProductId":"Google-Apps","SkuId":"1010020027","DisplayName":"Google Workspace Business Starter","Id":"Google-Apps.1010020027","Type":"License"}},{"DisplayName":"Google Workspace Business Standard","Identification":{"ProductId":"Google-Apps","SkuId":"1010020028","DisplayName":"Google Workspace Business Standard","Id":"Google-Apps.1010020028","Type":"License"}},{"DisplayName":"Google Workspace Business Plus","Identification":{"ProductId":"Google-Apps","SkuId":"1010020025","DisplayName":"Google Workspace Business Plus","Id":"Google-Apps.1010020025","Type":"License"}},{"DisplayName":"Google Workspace Enterprise Essentials","Identification":{"ProductId":"Google-Apps","SkuId":"1010060003","DisplayName":"Google Workspace Enterprise Essentials","Id":"Google-Apps.1010060003","Type":"License"}},{"DisplayName":"Google Workspace Enterprise Standard","Identification":{"ProductId":"Google-Apps","SkuId":"1010020026","DisplayName":"Google Workspace Enterprise Standard","Id":"Google-Apps.1010020026","Type":"License"}},{"DisplayName":"Google Workspace Enterprise Plus (formerly G Suite Enterprise)","Identification":{"ProductId":"Google-Apps","SkuId":"1010020020","DisplayName":"Google Workspace Enterprise Plus (formerly G Suite Enterprise)","Id":"Google-Apps.1010020020","Type":"License"}},{"DisplayName":"Google Workspace Essentials (formerly G Suite Essentials)","Identification":{"ProductId":"Google-Apps","SkuId":"1010060001","DisplayName":"Google Workspace Essentials (formerly G Suite Essentials)","Id":"Google-Apps.1010060001","Type":"License"}},{"DisplayName":"G Suite Business","Identification":{"ProductId":"Google-Apps","SkuId":"Google-Apps-Unlimited","DisplayName":"G Suite Business","Id":"Google-Apps.Google-Apps-Unlimited","Type":"License"}},{"DisplayName":"G Suite Basic","Identification":{"ProductId":"Google-Apps","SkuId":"Google-Apps-For-Business","DisplayName":"G Suite Basic","Id":"Google-Apps.Google-Apps-For-Business","Type":"License"}},{"DisplayName":"G Suite Lite","Identification":{"ProductId":"Google-Apps","SkuId":"Google-Apps-Lite","DisplayName":"G Suite Lite","Id":"Google-Apps.Google-Apps-Lite","Type":"License"}},{"DisplayName":"Google Apps Message Security","Identification":{"ProductId":"Google-Apps","SkuId":"Google-Apps-For-Postini","DisplayName":"Google Apps Message Security","Id":"Google-Apps.Google-Apps-For-Postini","Type":"License"}},{"DisplayName":"G Suite Enterprise for Education","Identification":{"ProductId":"101031","SkuId":"1010310002","DisplayName":"G Suite Enterprise for Education","Id":"101031.1010310002","Type":"License"}},{"DisplayName":"G Suite Enterprise for Education (Student)","Identification":{"ProductId":"101031","SkuId":"1010310003","DisplayName":"G Suite Enterprise for Education (Student)","Id":"101031.1010310003","Type":"License"}},{"DisplayName":"Google Drive storage 20 GB","Identification":{"ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-20GB","DisplayName":"Google Drive storage 20 GB","Id":"Google-Drive-storage.Google-Drive-storage-20GB","Type":"License"}},{"DisplayName":"Google Drive storage 50 GB","Identification":{"ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-50GB","DisplayName":"Google Drive storage 50 GB","Id":"Google-Drive-storage.Google-Drive-storage-50GB","Type":"License"}},{"DisplayName":"Google Drive storage 200 GB","Identification":{"ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-200GB","DisplayName":"Google Drive storage 200 GB","Id":"Google-Drive-storage.Google-Drive-storage-200GB","Type":"License"}},{"DisplayName":"Google Drive storage 400 GB","Identification":{"ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-400GB","DisplayName":"Google Drive storage 400 GB","Id":"Google-Drive-storage.Google-Drive-storage-400GB","Type":"License"}},{"DisplayName":"Google Drive storage 1 TB","Identification":{"ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-1TB","DisplayName":"Google Drive storage 1 TB","Id":"Google-Drive-storage.Google-Drive-storage-1TB","Type":"License"}},{"DisplayName":"Google Drive storage 2 TB","Identification":{"ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-2TB","DisplayName":"Google Drive storage 2 TB","Id":"Google-Drive-storage.Google-Drive-storage-2TB","Type":"License"}},{"DisplayName":"Google Drive storage 4 TB","Identification":{"ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-4TB","DisplayName":"Google Drive storage 4 TB","Id":"Google-Drive-storage.Google-Drive-storage-4TB","Type":"License"}},{"DisplayName":"Google Drive storage 8 TB","Identification":{"ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-8TB","DisplayName":"Google Drive storage 8 TB","Id":"Google-Drive-storage.Google-Drive-storage-8TB","Type":"License"}},{"DisplayName":"Google Drive storage 16 TB","Identification":{"ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-16TB","DisplayName":"Google Drive storage 16 TB","Id":"Google-Drive-storage.Google-Drive-storage-16TB","Type":"License"}},{"DisplayName":"Google Vault","Identification":{"ProductId":"Google-Vault","SkuId":"Google-Vault","DisplayName":"Google Vault","Id":"Google-Vault.Google-Vault","Type":"License"}},{"DisplayName":"Google Vault - Former Employee","Identification":{"ProductId":"Google-Vault","SkuId":"Google-Vault-Former-Employee","DisplayName":"Google Vault - Former Employee","Id":"Google-Vault.Google-Vault-Former-Employee","Type":"License"}},{"DisplayName":"Cloud Identity","Identification":{"ProductId":"101001","SkuId":"1010010001","DisplayName":"Cloud Identity","Id":"101001.1010010001","Type":"License"}},{"DisplayName":"Cloud Identity Premium","Identification":{"ProductId":"101005","SkuId":"1010050001","DisplayName":"Cloud Identity Premium","Id":"101005.1010050001","Type":"License"}},{"DisplayName":"Google Voice Starter","Identification":{"ProductId":"101033","SkuId":"1010330003","DisplayName":"Google Voice Starter","Id":"101033.1010330003","Type":"License"}},{"DisplayName":"Google Voice Standard","Identification":{"ProductId":"101033","SkuId":"1010330004","DisplayName":"Google Voice Standard","Id":"101033.1010330004","Type":"License"}},{"DisplayName":"Google Voice Premier","Identification":{"ProductId":"101033","SkuId":"1010330002","DisplayName":"Google Voice Premier","Id":"101033.1010330002","Type":"License"}}]';
$licensing | ConvertFrom-Json | Foreach-Object{ ConvertTo-Json -InputObject $_ };
Write-Information ("Total Licenses: {0}" -f ($licensing | ConvertFrom-Json).Count)
#endregion Build up result