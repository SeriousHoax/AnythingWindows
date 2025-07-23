# Replace a particular word or sentence from multiple file names at once

$folder = "E:\Downloads"
Get-ChildItem -Path $folder -File | ForEach-Object {
    $newName = $_.Name -replace 'anything-you-want-to-replace', 'anything-to-replace-with'
    Rename-Item -Path $_.FullName -NewName $newName
}