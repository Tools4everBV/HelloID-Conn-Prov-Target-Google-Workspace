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
$licensing = '[{"DisplayName":"Google Workspace Business Starter","Identification":{"Type":"License","ProductId":"Google-Apps","SkuId":"1010020027","DisplayName":"Google Workspace Business Starter","Id":"Google-Apps.1010020027"}},{"DisplayName":"Google Workspace Business Standard","Identification":{"Type":"License","ProductId":"Google-Apps","SkuId":"1010020028","DisplayName":"Google Workspace Business Standard","Id":"Google-Apps.1010020028"}},{"DisplayName":"Google Workspace Business Plus","Identification":{"Type":"License","ProductId":"Google-Apps","SkuId":"1010020025","DisplayName":"Google Workspace Business Plus","Id":"Google-Apps.1010020025"}},{"DisplayName":"Google Workspace Enterprise Essentials","Identification":{"Type":"License","ProductId":"Google-Apps","SkuId":"1010060003","DisplayName":"Google Workspace Enterprise Essentials","Id":"Google-Apps.1010060003"}},{"DisplayName":"Google Workspace Enterprise Standard","Identification":{"Type":"License","ProductId":"Google-Apps","SkuId":"1010020026","DisplayName":"Google Workspace Enterprise Standard","Id":"Google-Apps.1010020026"}},{"DisplayName":"Google Workspace Enterprise Plus (formerly G�Suite Enterprise)","Identification":{"Type":"License","ProductId":"Google-Apps","SkuId":"1010020020","DisplayName":"Google Workspace Enterprise Plus (formerly G�Suite Enterprise)","Id":"Google-Apps.1010020020"}},{"DisplayName":"Google Workspace Essentials (formerly G�Suite Essentials)","Identification":{"Type":"License","ProductId":"Google-Apps","SkuId":"1010060001","DisplayName":"Google Workspace Essentials (formerly G�Suite Essentials)","Id":"Google-Apps.1010060001"}},{"DisplayName":"Google Workspace Frontline","Identification":{"Type":"License","ProductId":"Google-Apps","SkuId":"1010020030","DisplayName":"Google Workspace Frontline","Id":"Google-Apps.1010020030"}},{"DisplayName":"G�Suite Business","Identification":{"Type":"License","ProductId":"Google-Apps","SkuId":"Google-Apps-Unlimited","DisplayName":"G�Suite Business","Id":"Google-Apps.Google-Apps-Unlimited"}},{"DisplayName":"G�Suite Basic","Identification":{"Type":"License","ProductId":"Google-Apps","SkuId":"Google-Apps-For-Business","DisplayName":"G�Suite Basic","Id":"Google-Apps.Google-Apps-For-Business"}},{"DisplayName":"G�Suite Lite","Identification":{"Type":"License","ProductId":"Google-Apps","SkuId":"Google-Apps-Lite","DisplayName":"G�Suite Lite","Id":"Google-Apps.Google-Apps-Lite"}},{"DisplayName":"Google Apps Message Security","Identification":{"Type":"License","ProductId":"Google-Apps","SkuId":"Google-Apps-For-Postini","DisplayName":"Google Apps Message Security","Id":"Google-Apps.Google-Apps-For-Postini"}},{"DisplayName":"Google Workspace for Education Standard","Identification":{"Type":"License","ProductId":"101031","SkuId":"1010310005","DisplayName":"Google Workspace for Education Standard","Id":"101031.1010310005"}},{"DisplayName":"Google Workspace for Education Standard (Staff)","Identification":{"Type":"License","ProductId":"101031","SkuId":"1010310006","DisplayName":"Google Workspace for Education Standard (Staff)","Id":"101031.1010310006"}},{"DisplayName":"Google Workspace for Education Standard (Extra Student)","Identification":{"Type":"License","ProductId":"101031","SkuId":"1010310007","DisplayName":"Google Workspace for Education Standard (Extra Student)","Id":"101031.1010310007"}},{"DisplayName":"Google Workspace for Education Plus","Identification":{"Type":"License","ProductId":"101031","SkuId":"1010310008","DisplayName":"Google Workspace for Education Plus","Id":"101031.1010310008"}},{"DisplayName":"Google Workspace for Education Plus (Staff)","Identification":{"Type":"License","ProductId":"101031","SkuId":"1010310009","DisplayName":"Google Workspace for Education Plus (Staff)","Id":"101031.1010310009"}},{"DisplayName":"Google Workspace for Education Plus (Extra Student)","Identification":{"Type":"License","ProductId":"101031","SkuId":"1010310010","DisplayName":"Google Workspace for Education Plus (Extra Student)","Id":"101031.1010310010"}},{"DisplayName":"Google Workspace for Education: Teaching and Learning Upgrade","Identification":{"Type":"License","ProductId":"101037","SkuId":"1010370001","DisplayName":"Google Workspace for Education: Teaching and Learning Upgrade","Id":"101037.1010370001"}},{"DisplayName":"Google Workspace for Education Plus - Legacy","Identification":{"Type":"License","ProductId":"101031","SkuId":"1010310002","DisplayName":"Google Workspace for Education Plus - Legacy","Id":"101031.1010310002"}},{"DisplayName":"Google Workspace for Education Plus - Legacy (Student)","Identification":{"Type":"License","ProductId":"101031","SkuId":"1010310003","DisplayName":"Google Workspace for Education Plus - Legacy (Student)","Id":"101031.1010310003"}},{"DisplayName":"Google Drive storage 20 GB","Identification":{"Type":"License","ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-20GB","DisplayName":"Google Drive storage 20 GB","Id":"Google-Drive-storage.Google-Drive-storage-20GB"}},{"DisplayName":"Google Drive storage 50 GB","Identification":{"Type":"License","ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-50GB","DisplayName":"Google Drive storage 50 GB","Id":"Google-Drive-storage.Google-Drive-storage-50GB"}},{"DisplayName":"Google Drive storage 200 GB","Identification":{"Type":"License","ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-200GB","DisplayName":"Google Drive storage 200 GB","Id":"Google-Drive-storage.Google-Drive-storage-200GB"}},{"DisplayName":"Google Drive storage 400 GB","Identification":{"Type":"License","ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-400GB","DisplayName":"Google Drive storage 400 GB","Id":"Google-Drive-storage.Google-Drive-storage-400GB"}},{"DisplayName":"Google Drive storage 1 TB","Identification":{"Type":"License","ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-1TB","DisplayName":"Google Drive storage 1 TB","Id":"Google-Drive-storage.Google-Drive-storage-1TB"}},{"DisplayName":"Google Drive storage 2 TB","Identification":{"Type":"License","ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-2TB","DisplayName":"Google Drive storage 2 TB","Id":"Google-Drive-storage.Google-Drive-storage-2TB"}},{"DisplayName":"Google Drive storage 4 TB","Identification":{"Type":"License","ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-4TB","DisplayName":"Google Drive storage 4 TB","Id":"Google-Drive-storage.Google-Drive-storage-4TB"}},{"DisplayName":"Google Drive storage 8 TB","Identification":{"Type":"License","ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-8TB","DisplayName":"Google Drive storage 8 TB","Id":"Google-Drive-storage.Google-Drive-storage-8TB"}},{"DisplayName":"Google Drive storage 16 TB","Identification":{"Type":"License","ProductId":"Google-Drive-storage","SkuId":"Google-Drive-storage-16TB","DisplayName":"Google Drive storage 16 TB","Id":"Google-Drive-storage.Google-Drive-storage-16TB"}},{"DisplayName":"Google Vault","Identification":{"Type":"License","ProductId":"Google-Vault","SkuId":"Google-Vault","DisplayName":"Google Vault","Id":"Google-Vault.Google-Vault"}},{"DisplayName":"Google Vault - Former Employee","Identification":{"Type":"License","ProductId":"Google-Vault","SkuId":"Google-Vault-Former-Employee","DisplayName":"Google Vault - Former Employee","Id":"Google-Vault.Google-Vault-Former-Employee"}},{"DisplayName":"Cloud Identity","Identification":{"Type":"License","ProductId":"101001","SkuId":"1010010001","DisplayName":"Cloud Identity","Id":"101001.1010010001"}},{"DisplayName":"Cloud Identity Premium","Identification":{"Type":"License","ProductId":"101005","SkuId":"1010050001","DisplayName":"Cloud Identity Premium","Id":"101005.1010050001"}},{"DisplayName":"Google Voice Starter","Identification":{"Type":"License","ProductId":"101033","SkuId":"1010330003","DisplayName":"Google Voice Starter","Id":"101033.1010330003"}},{"DisplayName":"Google Voice Standard","Identification":{"Type":"License","ProductId":"101033","SkuId":"1010330004","DisplayName":"Google Voice Standard","Id":"101033.1010330004"}},{"DisplayName":"Google Voice Premier","Identification":{"Type":"License","ProductId":"101033","SkuId":"1010330002","DisplayName":"Google Voice Premier","Id":"101033.1010330002"}}]';
$licensing | ConvertFrom-Json | Foreach-Object{ ConvertTo-Json -InputObject $_ };
Write-Information ("Total Licenses: {0}" -f ($licensing | ConvertFrom-Json).Count)
#endregion Build up result
