<#
.SYNOPSIS
Retrieves SSL certificate details from a specified web server.

.DESCRIPTION
The Get-WebServerCertificateInfo function establishes a TCP connection to a specified web server on port 443,
initiates an SSL handshake, and retrieves the SSL certificate details. It extracts and returns information such as
the common name, start date, end date, subject alternative name, thumbprint, and issuer name of the certificate.

.PARAMETER WebServer
The hostname or IP address of the web server from which to retrieve the SSL certificate details.

.PARAMETER Port
The port number to connect to on the web server. The default value is 443.

.EXAMPLE
Get-WebServerCertificateInfo -WebServer "www.example.com"
This command retrieves the SSL certificate details from the web server "www.example.com".

.NOTES
The function includes a timeout mechanism to handle cases where the connection to the web server cannot be established
within the specified timeout period (default is 1 second).

#>
# Function to retrieve certificate details from a web server with a timeout
function Get-WebServerCertificateInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$WebServer,
        [int]$Port = 443
    )
    try {
        # Create a TCP connection to the web server on port 443 with a timeout
        [int]$TimeoutSeconds = 1
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($WebServer, $Port, $null, $null)
        if (-not $asyncResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds), $false)) {
            throw "Connection timed out or could not connect."
        }

        $tcpClient.EndConnect($asyncResult)
        $sslStream = $tcpClient.GetStream()
        $sslStream = New-Object System.Net.Security.SslStream($sslStream, $false, { $true })

        # Authenticate as a client
        $sslStream.AuthenticateAsClient($WebServer)

        # Get the certificate
        $certificate = $sslStream.RemoteCertificate
        $x509Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificate)

        # Extract certificate details
        $subject = $x509Certificate.Subject
        $commonName = if ($subject -match "CN=(.*?)(,|$)") { $Matches[1] } else { "Unknown" }

        $sanExtension = ($x509Certificate.Extensions | Where-Object {
                $_.Oid.FriendlyName -eq "Subject Alternative Name"
            })

        $IssuerName = if ($x509Certificate.Issuer -match "CN=(.*?)(,|$)") { 
            
            if ($Matches[1] -eq "R11") {
                "R11 Let's Encrypt Authority"
            }
            else {
                $Matches[1]
            }
        
        }

        $certificateInfo = [PSCustomObject]@{
            testedServer           = $webServer    
            CommonName             = $commonName
            StartDate              = $x509Certificate.NotBefore
            EndDate                = $x509Certificate.NotAfter
            SubjectAlternativeName = if ($sanExtension) { $sanExtension.Format($false) -replace "DNS Name=", "" } else { "Not Available" }
            Thumbprint             = $x509Certificate.Thumbprint
            IssuerName             = $IssuerName
            message                = "Certificate retrieved successfully for $webServer."
            
        }

        # Close streams
        $sslStream.Close()
        $tcpClient.Close()

        return $certificateInfo
    }
    catch {
        Write-Error "Error retrieving certificate from $WebServer`: $_"

        # return empty object with null values
        return [PSCustomObject]@{
            testedServer           = $WebServer
            CommonName             = $null
            StartDate              = $null
            EndDate                = $null
            SubjectAlternativeName = $null
            Thumbprint             = $null
            IssuerName             = $null
            message                = "Error retrieving certificate for $WebServer"
        }
    }
}

# Example usage without specifying the port
Get-WebServerCertificateInfo -WebServer "google.com"

# Example usage with specifying the port
Get-WebServerCertificateInfo -WebServer "google.com" -Port 8443