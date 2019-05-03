# Job-Application-Tracking-Assistant
<br/><br/>
Deployment Instructions:<br/>
Go to the project folder, where the app.yaml of the project exists. <br/>
Connect to either a local MySQL instance or connect to Cloud SQL via the proxy. To start the proxy via command line execute first install the proxy client according to your operating system and execute :  cloud_sql_proxy -instances=[INSTANCE_CONNECTION_NAME]=tcp:3306. Steps for installing cloud proxy can be found in https://cloud.google.com/sql/docs/mysql-connect-proxy.<br/>
Go and change the database credentials and the cloud sql instance name in the settings.py file.<br/>
Run python manage.py makemigrations so that all the models/tables mentioned in models.py is created.<br/>
Run python manage.py migrate --run-syncdb to make sure all migrations are upfated in the CloudSql table.<br/>
Now you can deploy the app by running the command gcloud app deploy.<br/>
It is deployed, so you can open the public url of your cloud app to go over the Job Tracking Application or you could directly run gcloud app browse.<br/>
