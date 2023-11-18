# Link to original instruction url: https://phoenixnap.com/kb/install-java-windows#ftoc-heading-6

# Step 1:
    Double-click the downloaded file to start the installation.
    After running the installation file, the installation wizard welcome screen appears.
        Click Next to proceed to the next step.
        Choose the destination folder for the Java installation files or stick to the default path. Click Next to proceed.
        Wait for the wizard to finish the installation process until the Successfully Installed message appears. Click Close to exit the wizard.

# Step 2:
    Open the Start menu and search for environment variables.
    Select the Edit the system environment variables result.
    In the System Properties window, under the Advanced tab, click Environment Variables…
    Under the System variables category, select the Path variable and click Edit
    Click the New button and enter the path to the Java bin directory
    Click OK to save the changes and exit the variable editing window.

# Step 3:
    In the Environment Variables window, under the System variables category, click the New… button to create a new variable.
    Name the variable as JAVA_HOME
    In the variable value field, paste the path to your Java jdk directory and click OK.
    Confirm the changes by clicking OK in the Environment Variables and System properties windows.

# Step 4:
    Run the java -version command in the command prompt to make sure Java installed correctly