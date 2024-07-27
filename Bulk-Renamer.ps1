# Remove a particular word or sentence from multiple file names at once

$folder = "E:\Downloads"
$word_to_remove = "anything-you-want-to-remove"
Get-ChildItem -Path $folder | Rename-Item -NewName { $_.Name -replace $word_to_remove,"" }