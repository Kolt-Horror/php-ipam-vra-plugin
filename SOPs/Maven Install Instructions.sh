# Link to original instruction url: https://phoenixnap.com/kb/install-maven-windows

# Step 1:
    extract the Maven archive to a directory of your choice once the download is complete
    Recommended to use: C:\Program Files\Maven\

# Step 2:
    Open the Start menu and search for environment variables.
    Click the Edit the system environment variables result.
    Under the Advanced tab in the System Properties window, click Environment Variables.
    Click the New button under the System variables section to add a new system environment variable.
    Enter MAVEN_HOME as the variable name and the path to the Maven directory as the variable value. Click OK to save the new system variable.

# Step 3:
    Select the Path variable under the System variables section in the Environment Variables window. Click the Edit button to edit the variable.
    Click the New button in the Edit environment variable window.
    Enter %MAVEN_HOME%\bin in the new field. Click OK to save changes to the Path variable.
    Click OK in the Environment Variables window to save the changes to the system variables.
    In the command prompt, use the following command to verify the installation by checking the current version of Maven:
        mvn -version