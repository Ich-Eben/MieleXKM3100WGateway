//How to use:
//1. Set the Wlan of your Miele device with the Miele app.
//2. Do NOT add the device to the Mile app after it is connected to your network!
//3. Find out the IP-address of your Miele device
//4. Run this node app and brows to http://127.0.0.1/init/<IP-ADDRESS>/ (replace <IP-ADDRESS> with the IP-address of your Miele device)
//5. If you get an 403 error, you need to sniff the groupKy and groupId from the Miele app
//6. If the init succeeded you can now explore the data of your Miele device by browsing to http://127.0.0.1/explore/<IP-ADDRESS>/
//7. When you have found the data you are interested in you can extract it from other programs without the /explore option (http://127.0.0.1/<IP-ADDRESS>/<PATH>) This will give you the raw json data.

var app = require('express')();
var http = require('http').Server(app);
const request = require('superagent');
const crypto = require('crypto');
var dateFormat = require('dateformat');

const debugLog = false;

//You don't need to change this if you use the init function. But it is recommended if you can't trust your local network.
var groupKey = Buffer.from("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","hex");
var groupId =  Buffer.from("0000000000000000","hex");

const acceptHeader = "application/vnd.miele.v1+json";

function iterateToAllHrefs(obj, host, resourcePath) {
    for (var property in obj) {
        if (obj.hasOwnProperty(property)) {
            if (typeof obj[property] == "object") {
                iterateToAllHrefs(obj[property], host, resourcePath);
            } else {
                if (property == "href")  {
                    obj[property] = "<a href=" + "/explore/" + host + resourcePath + obj[property] + ">" + obj[property] + "</a>";
                }
            }
        }
    }
}


app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');

    // authorized headers for preflight requests
    // https://developer.mozilla.org/en-US/docs/Glossary/preflight_request
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();

    app.options('*', (req, res) => {
        // allowed XHR methods  
        res.header('Access-Control-Allow-Methods', 'GET, PATCH, PUT, POST, DELETE, OPTIONS');
        res.send();
    });
});

app.get('/init/*', function(req, response){
    if (debugLog) console.log('get: ' + req.url);
    var resourcePath = req.url;
    resourcePath = resourcePath.replace("/init","");
    //extract host
    var host = "";
    var regex = new RegExp('/[^/]+');
    let match = resourcePath.match(regex);
    if (match) {
        host = match[0];
        host = host.replace("/","");
    }
    resourcePath = resourcePath.replace(regex,"");
    if (host === "") {
        response.setHeader('Content-Type', 'application/json');
        response.send(JSON.stringify({error: "Host not set"},null,2));
        return;
    }
    try {
        let actDate = getCurrentTimeInHttpFormat();
        request.put("http://" + host + "/Security/Commissioning/")
                .set("Accept",acceptHeader)
                .set("Date",actDate)
                .set("User-Agent","Miele@mobile 2.3.3 Android")
                .set("Host",host)
                .set("Accept-Encoding","gzip")
                .send('{"GroupID":"' + groupId.toString("hex").toUpperCase() + '","GroupKey":"' + groupKey.toString("hex").toUpperCase() + '"}')
                .end(function (err,res) {
                     if (err) {
                        console.log(err);
                        response.setHeader('Content-Type', 'application/json');
                        let errorStr = "unknown";
                        if (res && res.statusCode) errorStr = res.statusCode;
                        response.send(JSON.stringify({error: errorStr},null,2));
                    } else {
                        response.setHeader('Content-Type', 'application/json');
                        response.send(res.body);
                    }
                });
            
    } catch(e) {
        response.end();
        console.log(e.stack);
   }
});

app.get('/*', function(req, response){
    if (req.url === "/favicon.ico") {
        response.end();
        return;
    }
    if (debugLog) console.log('get: ' + req.url);
    try {
        var explore = false;
        var resourcePath = req.url;
        if (resourcePath.startsWith("/explore")) {
            resourcePath = resourcePath.replace("/explore","");
            explore = true;
        }
        //extract host
        var host = "";
        var regex = new RegExp('/[^/]+');
        let match = resourcePath.match(regex);
        if (match) {
            host = match[0];
            host = host.replace("/","");
        }
        resourcePath = resourcePath.replace(regex,"");
        if (host === "") {
            response.setHeader('Content-Type', 'application/json');
            response.send(JSON.stringify({error: "Host not set"},null,2));
            return;
        }
        
        //generat signature
        let actDate = getCurrentTimeInHttpFormat();
        let signatureStr = "GET\n" + host + resourcePath + "\n\n" + acceptHeader + "\n" + actDate + "\n";
        let signature = crypto.createHmac("sha256", groupKey).update(Buffer.from(signatureStr,"ASCII")).digest('hex').toUpperCase();
        
        //send request to miele device
        request.get("http://" + host + resourcePath)
            .set("Accept",acceptHeader)
            .set("Date",actDate)
            .set("User-Agent","Miele@mobile 2.3.3 Android")
            .set("Host",host)
            .set("Authorization","MieleH256 " + groupId.toString("hex").toUpperCase() + ":" + signature)
            .set("Accept-Encoding","gzip")
            .parse(myParse)
            .end(function (err,res) {
                if (err) {
                    console.log(err);
                    response.setHeader('Content-Type', 'application/json');
                    let errorStr = "unknown";
                    if (res.statusCode) errorStr = res.statusCode;
                    response.send(JSON.stringify({error: errorStr},null,2));
                } else {
                    if (debugLog) console.log("Response status: " + res.statusCode);
                    let signature = res.header["x-signature"];
                    sig = signature.split(":");
                    if (sig.length >= 2) signature = sig[1];
                    if (debugLog) console.log("Response Signature: " + signature);
                    let data = decrypt(res.body,groupKey,signature);
                    let dataStr = data.toString("utf8");
                    if (debugLog) console.log("Data: ",dataStr);
                    
                    if (explore) {
                        //html with links
                        var jsonData = JSON.parse(dataStr);
                        iterateToAllHrefs(jsonData,host,resourcePath);
                        response.setHeader('Content-Type', 'text/html');
                        let jsonStr = JSON.stringify(jsonData,null,4);
                        var regex = new RegExp('\n', 'g');
                        jsonStr = jsonStr.replace(regex, '<br>');
                        jsonStr = jsonStr.replace(/    /g,"&nbsp;&nbsp;&nbsp;&nbsp;");
                        response.send("<html><head></head><body>" + jsonStr + "</body></html>");
                    } else {
                        //raw json
                        response.setHeader('Content-Type', 'application/json');
                        response.send(dataStr);
                    }
                }
            });
    } catch(e) {
        response.end();
        console.log(e.stack);
   }
});

http.listen(3000, function(){
    console.log('listening on *:3000');
});

var getCurrentTimeInHttpFormat = function() {
    let d = new Date();
    d.setTime(d.getTime() + d.getTimezoneOffset() * 60 * 1000);
    return dateFormat(d, "ddd, dd mmm yyyy HH:MM:ss") + " GMT";
}

var myParse = function(res, callback) {
    res.buffer = Buffer.from([]);
    res.on('data', function(chunk) { 
        res.buffer = Buffer.concat([res.buffer,Buffer.from(chunk,"utf8")]);
    });
    res.on('end', function () {
        callback(null, res.buffer);
    });
}

var decrypt = function (payload, groupKey, signature) {
    let key = groupKey.slice(0,groupKey.length / 2);
    let ivBuf = Buffer.from(signature,"hex");
    let iv = ivBuf.slice(0,ivBuf.length / 2);

    let decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let data = decipher.update(Buffer.concat([payload,Buffer.from("00","hex")])); //pad with 00 otherwise the result will be cut off
    return data;
}
