Function If-ScreenResolution {
    Param (
	[Parameter(Position = 0, Mandatory = $True)]
	[String]
	$min_resolution,
	[Parameter(Position = 1, Mandatory = $True)]
	[Bool]
	$not_suspect_if_multiple_monitors,
	[Parameter(Position = 2, Mandatory = $True)]
	[Bool]
	$require_multiple_monitors,
    
    )
    function Get-ScreenResolutions {            
        [void] [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")            
        [void] [Reflection.Assembly]::LoadWithPartialName("System.Drawing")            
        $Screens = [system.windows.forms.screen]::AllScreens            
        $resolutions = @()

        foreach ($Screen in $Screens) {            
            $DeviceName = $Screen.DeviceName            
            $Width  = $Screen.Bounds.Width            
            $Height  = $Screen.Bounds.Height            
            $IsPrimary = $Screen.Primary 
            $OutputObj = New-Object -TypeName PSobject             
            $OutputObj | Add-Member -MemberType NoteProperty -Name DeviceName -Value $DeviceName            
            $OutputObj | Add-Member -MemberType NoteProperty -Name Width -Value $Width            
            $OutputObj | Add-Member -MemberType NoteProperty -Name Height -Value $Height            
            $OutputObj | Add-Member -MemberType NoteProperty -Name IsPrimaryMonitor -Value $IsPrimary            
            $resolutions += $OutputObj            
        }            
        return $resolutions
    }
    $resolutions = Get-ScreenResolutions
}
