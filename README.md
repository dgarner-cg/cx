# Custom Scripts

Custom scripts for homelab and SMB purposes.
Most scripts are located on on-prem Gitlab repo until finalized and will be moved here.

## Chromium Secrets and History Decryptor:
This Python utility allows you to analyze and decrypt Chromium based browser information that is saved locally, 
this includes most of the popular Chromium based browsers, including Vivaldi, Chrome, Brave, etc..

You will be prompted to select what you want to analyze, secrets or history; select your browser and the utility 
will output the results of the analyization in console, exported to $basedir, or both.

You can also decrypt all your saved passwords in Chromium based browsers, under the secrets menu selection,
you will be prompted once your master key is displayed, if you would like to also view or export your locally saved
passwords in decrypted format.