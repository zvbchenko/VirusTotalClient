# Virus Total Client Project 
This project is an application that summerizes reports provided by VirusTotal platform. This app allows users to upload a text file as a list of hashes and generate a report from the data provided by querying VirusTotal's public API fpr the scan report of the hashes. 
## Technologies used and deployment instructions
The _command_ _line_ version is based on: Python(Flask), HTML, Redis, and Docker.
To deploy the _command_ _line_ version, go to the project's folder: 
1) Start Docker client 
```
open -a docker
```
2) Build and start containers  

```
docker-compose build --no-cache && docker-compose up
```

3) Open your browser and type in the address bar
``` 
http://localhost/
```

There is also a web version available hosted by AWS Elastic Beanstalk at:
```
http://antonapp-env.eba-rhxf3d3h.ca-central-1.elasticbeanstalk.com/
```


## How does it work?

1) At the front page user uploads the ```.txt``` file containing hashes that they want to check. Upon clicking the "Upload" button - the back-end starts preparing the report.

2) Due to limitations imposed by VirusTotal it is only possible to request information in batches of 4 every 15 seconds (4 requests per minute). To work around this limitation and to increase the efficiency of the application Redis server is used as a supporting cache. If the Redis query was unsuccessful, the hash value is attached to the batch of 4, that is going to be used in the Virus Total request

3) After accumulating 4 hashes, a request is sent towards the VirusTotal server. Once the server response is received it is analyzed. If the status code of the request is ```200```, the responses are formatted according the provided schema, and pushed to the list of results. The formatted responses are also pushed to Redis server. In the situation where VirusTotal's limitations of 500 queries per day for a single API key are met, and the back-end receives an empty response with status code of ```204```, the API key is switched (there are 4 keys available), and the request is repeated.
4) After accumulating the list of results, a csv file with the results is accumulated. A csv file is then turned into the HTML table 

5) The browser then transitions to the output page where the HTML formed at the previous step is presented. 


## Project Structure

```
.
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── server.py
├── command_line_client.py
├── templates
│   └── out_of_req.html
├── uploads
└── Demo.mp4
```
