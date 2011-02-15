// NoFix 0.1 by Bram Bonné

const LOG_LEVEL = 2; //0: everything; 0.5: passing & blocking; 1: warning; 2: error; 3: nothing
const log_to_file = true; // Whether blocks & passes should be kept in a file (for statistics)
const block_notify = false; // Whether the user should be notified of blocks
const log_subdomain_cookies = false; // Whether it should be logged when a website sets a cookie for its parent domain (log_to_file must be enabled for this)
const log_delays = true; // Whether delays incurred by the extension should be logged

const SKIP_SESSION_ID_CHECK = false; // If this is true, all cookies will be checked (not only the ones containing session ID's)

// Database
var storageService = null;
var normalDb = null; // Database for normal browsing
var privateDb = null; // Database for private browsing
var currentDb = null; // Database currently in use
var cookieWriteCache = []; // Cookies not yet written to the database (very short array)

// Log file (for keeping statistics)
logFile = null;

// Private browsing mode (use different database while the user is in this mode)
var private_browsing = false;

// Profiling
var requestDelays = 0;
var responseDelays = 0;
var singleRequestDelays = 0;
var singleResponseDelays = 0;
var nrequests = 0;
var nresponses = 0;
var nsinglerequests = 0;
var nsingleresponses = 0;
var nentropycheck = 0;
var cookiesetcount = 0;

function log(msg, level)
{ // Log messages to the console in firefox
    if (level == undefined)
        level = 0;
    if (LOG_LEVEL > level)
        return;
    var levelstring = "LOG "
    switch(level) {
        case 1:
            levelstring = "WARN"
            break;
        case 2:
            levelstring = "ERR "
    }
    var logstring = "NOFIX " + levelstring + ": " + msg + "\n";
    dump(logstring);
    var console = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
    console.logStringMessage(logstring);
}

function log_file_UI(cookie, domain, passed)
{ // Log passes and blocks to a logfile, for later statistics
  // Does not log when in private browsing mode
    if (log_to_file && !private_browsing) {
        if (passed)
            logString = "P"
        else
            logString = "B"
        logString += ";"+cookie+";"+domain+"=\n";
        logFile.write(logString, logString.length);
    }
    if (!passed && block_notify)
        alert("A cookie was blocked: " + cookie + " for domain " + domain);
}

function log_subdomain_cookie(subdomain, parentdomain)
{ // Log setting of a cookie for a parent domain to a logfile
  // Does not log when in private browsing mode
    if (log_to_file && log_subdomain_cookies && !private_browsing) {
        logString = "S;" + subdomain + ";" + parentdomain + ";" + cookiesetcount + "=\n";
        dump(logString);
        logFile.write(logString, logString.length);
    }
}

function log_delay(millisecs, domain, isRequest)
{ // Log delays incurred by the extension
    if (log_to_file && log_delays) {
        if (isRequest)
            logString = "D"
        else
            logString = "d"
        logString += ";"+millisecs+";"+domain+"=\n";
        logFile.write(logString, logString.length);
    }
}

function is_TLD(domain)
{   // Checks whether the domain is a Top-level domain (.com, .co.uk,...)
    try {
        if (domain == 'localhost')
            return false;
        var eTLDService = Components.classes["@mozilla.org/network/effective-tld-service;1"].getService(Components.interfaces.nsIEffectiveTLDService);
        tld = eTLDService.getPublicSuffixFromHost(domain);
        return (tld == domain);
	}
	catch(e)
    {
    	log ("is_TLD failed: " + e);
    	return false;
    }   
}

function is_subdomain(subdomain, parent)
{   // Checks whether parent is a valid parent domain for subdomain
    // We cannot do this using just regular expressions. Some more checking is required
    // First alleviate the port numbers
    subdomain = subdomain.split(':')[0];
    parent = parent.split(':')[0];
    // Now search for the substring
    var index = subdomain.search(parent);
    if (index == -1) {
        return false;
    }
    if (!(index == [0] || subdomain[index-1] == '.')) {
        return false;
    }
    if (index + parent.length != subdomain.length) {
        return false;
    }
    if (is_TLD(parent)) {
        return false;
    }
    // If all tests are OK
    return true;
}

function db_create(filename)
{ // Creates the database if it does not exist yet. Returns the connection
    var file = Components.classes["@mozilla.org/file/directory_service;1"]  
                      .getService(Components.interfaces.nsIProperties)  
                      .get("ProfD", Components.interfaces.nsIFile);
    file.append(filename+".sqlite");
    storageService = Components.classes["@mozilla.org/storage/service;1"].getService(Components.interfaces.mozIStorageService);  
    var connection = storageService.openDatabase(file);
    connection.executeSimpleSQL(
        "CREATE TABLE IF NOT EXISTS Cookie (\
        domain VARCHAR(256),\
        cookie VARCHAR(256),\
        value VARCHAR(256),\
        expdate INTEGER,\
        PRIMARY KEY (domain, cookie))");
    return connection;
}

function db_drop(connection)
{ // Removes all data from the database
    connection.executeSimpleSQL("DROP TABLE Cookie");
}

function db_clean_session(connection)
{ // Remove non-persistent and expired cookies
    try {
        stmt = connection.createStatement(
                "DELETE FROM Cookie\
                WHERE (expdate IS NULL) OR (expdate <= :date)");
        var now = new Date();
        stmt.params.date = now.getTime();
        stmt.execute();
    } catch (e) {
        log("Could not remove expired cookies: " + e, 2);
    }
}

function db_update_cookie(domain, cookie, value, expdate)
{
	stmt = currentDb.createStatement(
        "UPDATE cookie SET\
        value = :value, expdate = :expdate\
        WHERE domain = :domain and cookie = :cookie");
    stmt.params.domain = domain;
    stmt.params.cookie = cookie;
    stmt.params.value = value;
    stmt.params.expdate = expdate;
    try {
    	// Execute this query asynchronously, so we don't let the user wait
        stmt.executeAsync({
        	handleError:
		    	function(e) {
		    		log("Something is wrong with the database: " + e, 3);
		    	},
        	handleCompletion:
	    		function(r) {
	    			cookieWriteCache.splice(cookieWriteCache.indexOf(domain+";"+cookie+";"+value), 1) // Removes from cookieWriteCache
	    		}
        	});
    } catch (e) {
	    log("Something is wrong with the database: " + e, 3);
    }
}

function db_add_cookie(domain, cookie, value, expdate)
{
    try {
        stmt = currentDb.createStatement(
            "INSERT INTO cookie\
            VALUES(:domain, :cookie, :value, :expdate)"
        );
    } catch (e) {  
        log("Could not prepare database statement! db = " + currentDb + "; error is: " + e, 2);
        return;
    }
    stmt.params.domain = domain;
    stmt.params.cookie = cookie;
    stmt.params.value = value;
    stmt.params.expdate = expdate;
    try {
    	// First write it to the cache. Since database inserts are handled asynchronously,
    	// we want the next request to be able to see the cookie, regardless of
    	// whether it is already written to the database
    	cookieWriteCache.push(domain+";"+cookie+";"+value);
    	// Execute asynchronously so no delays are introduced in page requests
    	stmt.executeAsync({
    		handleError:
		    	function(e) {
		    		db_update_cookie(domain, cookie, value, expdate);
		    	},
	    	handleCompletion:
	    		function(r) {
	    			cookieWriteCache.splice(cookieWriteCache.indexOf(domain+";"+cookie+";"+value), 1) // Removes from cookieWriteCache
	    		}
    	});
    }
    catch(e) {
    	// Cookie is already in the database, update it
    	db_update_cookie(domain, cookie, value, expdate);
    }
}

function db_cookie_is_valid(domain, cookie, value)
{
    stmt = currentDb.createStatement(
        "SELECT domain FROM Cookie\
        WHERE cookie = :cookie AND value = :value\
        AND ((expdate IS NULL) OR (expdate >= :date))"); // expdate == null for non-persistent cookies
    stmt.params.cookie = cookie;
    stmt.params.value = value;
    var now = (new Date()).getTime();
    stmt.params.date = now;
    try {
        while (stmt.executeStep()) { // Iterate over all results
            // Check whether the result contains a valid domain
            var cookieDomain = stmt.row.domain;
            if (is_subdomain(domain, cookieDomain)) {
                // Valid cookie found, pass
                stmt.reset();
                return true; 
            }
        }
        // No results returned, or none contained a valid domain
        // Check the main memory (cookies not yet written to the database)
        // This list is very small (if not 0) and will as such not introduce a big overhead
        for (i in cookieWriteCache) {
        	cacheCookie = cookieWriteCache[i].split(';');
        	if (is_subdomain(domain, cacheCookie[0]) && cookie == cacheCookie[1] && value == cacheCookie[2])
        		return true;
		}
    	// Cookie nowhere to be found
        return false;
    } catch (e) {
        log("Something is wrong with the database: " + e, 3);
        return false;
    }
}

function parse_date(dateString)
{ // Converts a date string to an integer which can be handled by javascript
    // First, let JavaScript try if it can handle the string already
    value = Date.parse(dateString);
    if (!isNaN(value))
        return value;
    log("Extra date parsing needed for " + dateString);
    // JavaScript itself was unable to parse the date, this function will take a little longer
    // Some websites set the date like 30-Nov-1988, whereas it should be 30 Nov 1988
    dateString = dateString.replace(/-/gi,' ');
    dateString = dateString.replace(/GMT /, 'GMT-');// Undo the replacement for GMT (my regex-fu is not that great)
    value = Date.parse(dateString);
    log("Newly parsed: " + dateString);
    if (!isNaN(value))
        return value;
    // If all fails, make the cookie persistent for a month (this is a compromise)
    log("Parsing of date "+dateString+" failed, making it valid for a month.", 1);
    var now = new Date();
    return now.getTime() + 30*24*60*60*1000;
}

function extract_expiration_date(cookie)
{ // Returns the expiration date as epoch time
    var dateMatch = /expires=([^;]+)/i.exec(cookie);
    if (dateMatch != null && dateMatch[1] != null) {
        return parse_date(dateMatch[1]);
    } else {
        return null;
    }
}

function extract_cookie_domain(cookie)
{ // Searches for a domain in the cookie
    var cookiedomain = /domain=([^;]+)/i.exec(cookie);
    if (cookiedomain != null && cookiedomain[1] != null) { // domain is set in cookie
        // trim '.'
        return cookiedomain[1].replace(/^[.]/,'');
    } else {
        return null;
    }
}

function relative_entropy(string)
{ // Returns the entropy of a string compared to its ideal entropy
  // Adapted from the python code which can be found at http://is.gd/ibuYh and from Wannes Meert's randomness.py
  // This function is used for calculating whether a string is possibly a session cookie
    entropy = 0;
    // Count equal characters
    var bins = [];
    for (i in string) {
        c = string[i];
        if (c in bins)
            bins[c] += 1;
        else
            bins[c] = 1;
    }
    for (i in bins) {
        prob = bins[i] / string.length;
        entropy -= prob * Math.log(prob);
    }
    
    idealEntropy = -1.0 * Math.log(1.0/string.length);
    return entropy/idealEntropy; 
}

function encoding_size_score(string)
{ // Returns the number of bits that would be neede to encode the string
  // Adapted from Wannes Meert's randomness.py
  // This function is used for calculating whether a string is possibly a session cookie
    // Randomness constants
	const punctuation = "~!#%^@&$*_()?-+=";
	const ascii_lowercase = "abcdefghijklmnopqrstuvwxyz";
	const ascii_uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	
	var charset = 0;
    
	var checkedstring = string//.substring(0, string.length);
	var newstring = checkedstring.replace(/[a-z]+/g,'');
	if (newstring.length < checkedstring.length) {
		checkedstring = newstring;
		charset += 26
	}
	newstring = checkedstring.replace(/[A-Z]+/g,'');
	if (newstring.length < checkedstring.length) {
		checkedstring = newstring;
		charset += 26
	}
	newstring = checkedstring.replace(/[0-9]+/g,'');
	if (newstring.length < checkedstring.length) {
		checkedstring = newstring;
		charset += 10
	}
	newstring = checkedstring.replace(/[~!#%^@&$*_()?\-+=]+/g,'');
	if (newstring.length < checkedstring.length) {
		checkedstring = newstring;
		charset += 17
	}
	if (checkedstring.length > 0)
		charset += 100 - (26+26+17+10);

	bits = Math.log(charset) * (string.length / Math.log(2))
	
    if (bits >= 128)
        return 0.9
    else if (bits >= 64)
        return 0.6
    else if (bits >= 56)
        return 0.2
    else if (bits >= 28)
        return 0.1
    else
        return 0
}

function is_session_cookie(cookieName, cookieValue)
{ // Checks whether the cookie is a session cookie
  // This code was adapted from code found in SessionShield by Nick Nikiforakis
    cookieName = cookieName.toLowerCase();
    
    // Make an exception for web analysis (e.g. Google's analytics) cookies
    // because they are set via JavaScript and fetched via HTTP
    // These cookies usually start with an underscore ('_')
    if (cookieName[0] == '_') {
    // Alternatively, the next test checks only for Google Analytics cookies
    //if (/^__utm[abczvkx]/.exec(cookieName)) {
        return false;
    }
    // Check if the cookie is a well-known *non*-SID name
    const known_not_sid = ['locale','skin','fontsize','x-referer','pref','act','presence'];
    for (i in known_not_sid) {
        if (cookieName == known_not_sid[i])
            return false;
    }
    
    // Check if the cookie name is a well-known SID name
    const known_sid = ['phpsessid','aspsessionid', 'asp.net_session', 'jspsession','aspxanonymous'];
    for (i in known_sid) {
        if (cookieName == known_sid[i])
            return true;
    }
    // Difference from original code: do not check for values which are common
    // in non-SID's, because chances are that these strings will appear in a
    // SID-string. We want as little false negatives as possible.

    // Good SID's should contain both numbers and characters
    // If this is not the case, assume this is not a session cookie
    if (/[0-9]/.exec(cookieValue) == null || /[a-zA-Z]/.exec(cookieValue) == null)
        return false;
    // If the previous was OK, and the name contains 'sess', we
    // can be pretty sure this is a SID, as long as the value is long enough
    if (cookieName.indexOf('sess') >= 0 && cookieValue.length > 10)
        return true;
	nentropycheck++;
	nsingleresponses++;
	single_start = new Date();
    if ((0.5*relative_entropy(cookieValue) + encoding_size_score(cookieValue)) >= 0.72) {
    	single_end = new Date();
        singleResponseDelays += single_end.getTime() - single_start.getTime()
        return true;
    }
    single_end = new Date();
    singleResponseDelays += single_end.getTime() - single_start.getTime()
    // If the previous tests failed, treat the cookie as not containing a SID
    return false;
}

function add_cookie(domain, cookie)
{ // Extracts the necessary information from the cookie and adds it to the database
    cookiesetcount++;
    var cookieData = /^[^;]+/.exec(cookie)[0];
    cookieData = cookieData.split('=');
    var cookieName = cookieData[0];
    var cookieValue = cookieData.slice(1).join('='); // Because '=' might appear inside the value
    if (!SKIP_SESSION_ID_CHECK && !is_session_cookie(cookieName, cookieValue)) {
        return; // Only add session cookies
    }
    var expirationDate = extract_expiration_date(cookie);
    log("Cookie being set: " + cookie + " for domain " + domain);
    var start = 
    db_add_cookie(domain, cookieName, cookieValue, expirationDate);
}

function handle_new_cookie(cookie, requestdomain)
{ // Allows for asynchronous handling of new cookies
	// Search for a domain in the cookie itself (to be able to set cookies for a parent domain)
	cookiedomain = extract_cookie_domain(cookie);
    if (cookiedomain == null)
        cookiedomain = requestdomain;
    else { // Check whether the parent domain dictated by the cookie is valid
        // The second part of this if-test will almost never be the case (it never occured while testing the plugin), so we let lazy evaluation do its work
        if (!is_subdomain(requestdomain, cookiedomain) && !is_subdomain(cookiedomain, requestdomain)) {
            log("Probably an evil domain (" + domain + ") trying to set a cookie: " + cookie, 1);
            return;
        } else
        	// Log this subdomain setting for statistical purposes
        	log_subdomain_cookie(cookiedomain, requestdomain);
    }
    // Everything went well, now it's time to add the cookie to our database.
    // The reason we add the cookie regardless of whether it's a session
    // cookie is that later adaptations/configuration settings might need
    // the cookie anyhow.
    add_cookie(cookiedomain, cookie);
}

function cookie_is_allowed(domain, cookieName, cookieValue)
{ // Checks whether the cookie can pass
	// Check if it is in our database
	if (db_cookie_is_valid(domain, cookieName, cookieValue))
		return true; // Cookie is in the cookie database
    else if (!SKIP_SESSION_ID_CHECK && !is_session_cookie(cookieName, cookieValue))
        return true; // Only block session cookies
    // Cookie is a session cookie, and is not in our database
    else
    	return false;
}

var httpRequestObserver =
{   // Called whenever a HTTP request is sent
    observe: function(subject, topic, data) 
    {
        if (topic != "http-on-modify-request") {
            log("Not a HTTP request, while httpRequestObserver was called: " + subject + ", " + topic, 0.5);
            return;
        }
        var httpChannel = subject.QueryInterface(Components.interfaces.nsIHttpChannel);
        var cookieSvc = Components.classes["@mozilla.org/cookieService;1"].getService(Components.interfaces.nsICookieService);
        //                                                  strip port
        var domain = httpChannel.getRequestHeader("Host").split(':')[0];
        // FromHTTP because we also want to check HTTP-only cookies
        var originalCookie = cookieSvc.getCookieStringFromHttp(subject.URI, null, null);
        if (originalCookie == null) {
            // No cookie sent with the request, nothing to be done
            return;
        }
        nrequests++;
        var start = new Date();
        var newCookie = "";
        var cookies = originalCookie.split(";");
        for (i in cookies) {
        	nsinglerequests++;
        	single_start = new Date();
            var cookie = cookies[i];
            // Clean up the cookie, strip whitespace
            cookie = cookie.replace(/^\s/,'').replace(/\s$/,'');
            cookieData = cookie.split('=');
            var cookieName = cookieData[0];
            var cookieValue = cookieData.slice(1).join('=');
            if (cookie_is_allowed(domain, cookieName, cookieValue)) {
                newCookie += cookie + ';';
                log ("Cookie passed: " + cookie + " for domain " + domain, 0.5);
                log_file_UI(cookieName, domain, true);
            } else {
                log("Cookie was blocked: " + cookie + " for domain " + domain, 1);
                log_file_UI(cookieName, domain, false);
            }
            single_end = new Date();
            singleRequestDelays += single_end.getTime() - single_start.getTime()
        }
        httpChannel.setRequestHeader("Cookie", newCookie, false);
        var end = new Date();
        delay = end.getTime() - start.getTime()
        requestDelays += delay
        log_delay(delay, domain, true);
    }
};

var httpResponseObserver =
{ // Called whenever a HTTP response is received
    observe: function(subject, topic, data)
    {
        if (topic != "http-on-examine-response") // Not a response
            return;  
        var httpChannel = subject.QueryInterface(Components.interfaces.nsIHttpChannel);
        // Search for cookies being set
        try {
            var cookies = httpChannel.getResponseHeader("Set-Cookie").split('\n');
        } catch (exception) {// No cookies set
            return;
        }
        var start = new Date();
        // If we got this far, cookies were found
        nresponses++;
        // Get the domain where the request came from            remove port
        var requestdomain = httpChannel.getRequestHeader("Host").split(':')[0];
        // Iterate over all cookies found
        for (i in cookies) {
            var cookie = cookies[i];
            handle_new_cookie(cookies[i], requestdomain);
        }
        var end = new Date();
        delay = end.getTime() - start.getTime()
        responseDelays += delay
        log_delay(delay, requestdomain, false);
        dump("Delays: req " + requestDelays*1.0/nrequests + " (single: " + singleRequestDelays*1.0/nsinglerequests + "), resp " + responseDelays*1.0/nresponses + " (single : " + singleResponseDelays*1.0/nsingleresponses + ") Entropy checks: " + nentropycheck*100.0/nsingleresponses + "%\n");
    }
};

var shutdownObserver =
{ // Called when Firefox exits
    observe: function(subject, topic, data)
    {
        log ("Shutting down");
        db_clean_session(normalDb);
        db_drop(privateDb);
        try {
            currentDb.close();
            log("Database closed");
        } catch (e) {
            log ("Could not close database: " +e, 2);
        }
        try {
            privateDb.close();
            log("Private database closed");
        } catch (e) {
            log ("Could not close private database: " +e, 2);
        }
        if (log_to_file) {
            try {
                logFile.close();
            } catch (e) {
                log("Could not close log file: " +e, 2);
            }
        }
        log("Cleanup ready");
    }
}

var privateBrowsingObserver =
{ // Called on private browsing state change
    observe : function(subject, topic, data) {
        if (data == "enter") {
            private_browsing = true;
            // Create the private db table
            privateDb = db_create("nofix-private");
            currentDb = privateDb;
            log("Private browsing enabled");
        } else if (data == "exit") {
            private_browsing = false;
            // Remove all data from the private db
            db_drop();
            // Reset state
            currentDb = normalDb;
            log("Private browsing disabled");
        }
    }
};
/*
 * Plugin initialization starts here
 */

// Create the database connection
normalDb = db_create("nofix");
currentDb = normalDb;
    
// Open the log file
if (log_to_file) {
    file = Components.classes["@mozilla.org/file/directory_service;1"]  
                      .getService(Components.interfaces.nsIProperties)  
                      .get("ProfD", Components.interfaces.nsIFile);  
    file.append("nofix.log");
    logFile = Components.classes["@mozilla.org/network/file-output-stream;1"].createInstance(Components.interfaces.nsIFileOutputStream);
    // Append to file
    try {
        logFile.init(file, 0x02 | 0x10, 0666, 0);
    } catch(e) { // File does not yet exist, create it
        logFile.init(file, 0x02 | 0x08 | 0x20, 0666, 0);
    }
}
                      
// Add the observers for HTTP requests
var observerService = Components.classes["@mozilla.org/observer-service;1"].getService(Components.interfaces.nsIObserverService);
observerService.addObserver(httpRequestObserver, "http-on-modify-request", false);
observerService.addObserver(httpResponseObserver, "http-on-examine-response", false);
// Add the observer for application shutdown
observerService.addObserver(shutdownObserver, "quit-application-requested", false);
// Add the observer for private browsing mode
observerService.addObserver(privateBrowsingObserver, "private-browsing", false);

// TEMPORARY DEBUG CODE, TODO: REMOVE ME!
start = new Date();
var errorstring = ""
for (a = 0; a < 500; a++) {
	errorstring = "";
	try {
		const session_cookies = ["phpsessid=20", "definitely_session=n0p4ssw0rd1sth1s", "randomythingy=hfvcIjmcJDX9LzdQ", "reddit=4080389%2C2011-02-14T08%3A36%3A21%2C8fe3c8ea18bd2b8a82d1aaac192279d5d8aa6a4d"]
		for (d in session_cookies) {
			cook = session_cookies[d].split('=');
			if (!is_session_cookie(cook[0], cook[1])) {
				errorstring += "Not a session cookie: " + session_cookies[d] + "\n"
			}
		}
		const non_session_cookies = ["locale=eenheelmoeilijkelangetaal", "hi=#0Rt"];
		for (d in non_session_cookies) {
			//dump(i);
			cook = non_session_cookies[d].split('=');
			if (is_session_cookie(cook[0], cook[1]))
				errorstring += "A session cookie: " + non_session_cookies[d] + "\n"
		}
	} catch (e) {
		errorstring += e;
	}
}
end = new Date();
delay = end.getTime() - start.getTime()
alert("Delay was: " + delay + "//" + errorstring);
// END OF TEMPORARY DEBUG CODE

// All done
log("NoFix plugin started");
