// NoFix 0.9 by Bram Bonné

// Create own namespace
var NoFix = {};

NoFix.LOG_LEVEL = 1; //0: everything; 0.5: passing & blocking; 1: warning; 2: error; 3: nothing
NoFix.log_subdomain_cookies = false; // Whether it should be logged when a website sets a cookie for its parent domain (file logging must be enabled for this)
NoFix.log_delays = true; // Whether delays incurred by the extension should be logged
NoFix.TEST_PLUGIN = false; // Will run some tests and output the result in an alert before starting FF

// Database
NoFix.storageService = null;
NoFix.normalDb = null; // Database for normal browsing
NoFix.privateDb = null; // Database for private browsing
NoFix.currentDb = null; // Database currently in use
NoFix.cookieWriteCache = []; // Cookies not yet written to the database (very short array)

// Log file (for keeping statistics)
NoFix.logFile = null;

// Private browsing mode (use different database while the user is in this mode)
NoFix.private_browsing = false;

// Profiling
NoFix.requestDelays = 0;
NoFix.responseDelays = 0;
NoFix.singleRequestDelays = 0;
NoFix.singleResponseDelays = 0;
NoFix.nrequests = 0;
NoFix.nresponses = 0;
NoFix.cookiesetcount = 0;
NoFix.ncookierequests = 0;
NoFix.ncookieresponses = 0;
NoFix.nsinglerequests = 0;

NoFix.log = function(msg, level)
{ // Log messages to the console in firefox
    if (level == undefined)
        level = 0;
    if (NoFix.LOG_LEVEL > level)
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

NoFix.log_file_UI = function(cookie, domain, passed)
{ // Log passes and blocks to a logfile, for later statistics
  // Does not log when in private browsing mode
    if (NoFix.prefManager.getBoolPref("extensions.nofix.logtofile") && !NoFix.private_browsing) {
        if (passed)
            logString = "P"
        else
            logString = "B"
        logString += ";"+cookie+";"+domain+"=\n";
        NoFix.logFile.write(logString, logString.length);
    }
}

NoFix.log_subdomain_cookie = function(subdomain, parentdomain)
{ // Log setting of a cookie for a parent domain to a logfile
  // Does not log when in private browsing mode
    if (NoFix.prefManager.getBoolPref("extensions.nofix.logtofile") && NoFix.log_subdomain_cookies && !NoFix.private_browsing) {
        logString = "S;" + subdomain + ";" + parentdomain + ";" + cookiesetcount + "=\n";
        dump(logString);
        NoFix.logFile.write(logString, logString.length);
    }
}

NoFix.log_delay = function(millisecs, domain, isRequest)
{ // Log delays incurred by the extension
    if (NoFix.prefManager.getBoolPref("extensions.nofix.logtofile") && NoFix.log_delays) {
        if (isRequest)
            logString = "D"
        else
            logString = "d"
        logString += ";"+millisecs+";"+domain+"=\n";
        NoFix.logFile.write(logString, logString.length);
    }
}

NoFix.is_TLD = function(domain)
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
    	NoFix.log ("is_TLD failed: " + e);
    	return false;
    }   
}

NoFix.is_subdomain = function(subdomain, parent)
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
    if (NoFix.is_TLD(parent)) {
        return false;
    }
    // If all tests are OK
    return true;
}

NoFix.db_create = function(filename)
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

NoFix.db_drop = function(connection)
{ // Removes all data from the database
    connection.executeSimpleSQL("DROP TABLE Cookie");
}

NoFix.db_clean_session = function(connection)
{ // Remove non-persistent and expired cookies
    try {
        stmt = connection.createStatement(
                "DELETE FROM Cookie\
                WHERE (expdate IS NULL) OR (expdate <= :date)");
        var now = new Date();
        stmt.params.date = now.getTime();
        stmt.execute();
    } catch (e) {
        NoFix.log("Could not remove expired cookies: " + e, 2);
    }
}

NoFix.db_update_cookie = function(domain, cookie, value, expdate)
{
	stmt = NoFix.currentDb.createStatement(
        "UPDATE cookie SET\
        value = :value, expdate = :expdate\
        WHERE domain = :domain and cookie = :cookie");
    stmt.params.domain = domain;
    stmt.params.cookie = cookie;
    stmt.params.value = value;
    stmt.params.expdate = expdate;
    try {
        // First write it to the cache. Since database inserts are handled asynchronously,
    	// we want the next request to be able to see the cookie, regardless of
    	// whether it is already written to the database
    	NoFix.cookieWriteCache.push(domain+";"+cookie+";"+value);
    	// Execute this query asynchronously, so we don't let the user wait
        stmt.executeAsync({
        	handleError:
		    	function(e) {
		    		NoFix.log("Something is wrong with the database: " + e, 3);
		    	},
        	handleCompletion:
	    		function(r) {
	    			NoFix.cookieWriteCache.splice(NoFix.cookieWriteCache.indexOf(domain+";"+cookie+";"+value), 1) // Removes from cookieWriteCache
	    		}
        	});
    } catch (e) {
	    NoFix.log("Something is wrong with the database: " + e, 3);
    }
}

NoFix.db_add_cookie = function(domain, cookie, value, expdate)
{
    try {
        stmt = NoFix.currentDb.createStatement(
            "INSERT INTO cookie\
            VALUES(:domain, :cookie, :value, :expdate)"
        );
    } catch (e) {  
        NoFix.log("Could not prepare database statement! db = " + currentDb + "; error is: " + e, 2);
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
    	NoFix.cookieWriteCache.push(domain+";"+cookie+";"+value);
    	// Execute asynchronously so no delays are introduced in page requests
    	stmt.executeAsync({
    		handleError:
		    	function(e) {
		    		NoFix.db_update_cookie(domain, cookie, value, expdate);
		    	},
	    	handleCompletion:
	    		function(r) {
	    			NoFix.cookieWriteCache.splice(NoFix.cookieWriteCache.indexOf(domain+";"+cookie+";"+value), 1) // Removes from cookieWriteCache
	    		}
    	});
    }
    catch(e) {
    	// Cookie is already in the database, update it
    	NoFix.db_update_cookie(domain, cookie, value, expdate);
    }
    return true;
}

NoFix.db_cookie_is_valid = function(domain, cookie, value)
{
    stmt = NoFix.currentDb.createStatement(
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
            if (NoFix.is_subdomain(domain, cookieDomain)) {
                // Valid cookie found, pass
                stmt.reset();
                return true; 
            }
        }
        // No results returned, or none contained a valid domain
        // Check the main memory (cookies not yet written to the database)
        // This list is very small (if not 0) and will as such not introduce a big overhead
        for (i in NoFix.cookieWriteCache) {
        	cacheCookie = NoFix.cookieWriteCache[i].split(';');
        	if (NoFix.is_subdomain(domain, cacheCookie[0]) && cookie == cacheCookie[1] && value == cacheCookie[2])
        		return true;
		}
    	// Cookie nowhere to be found
        return false;
    } catch (e) {
        NoFix.log("Something is wrong with the database: " + e, 3);
        return false;
    }
}

NoFix.parse_date = function(dateString)
{ // Converts a date string to an integer which can be handled by javascript
    // First, let JavaScript try if it can handle the string already
    value = Date.parse(dateString);
    if (!isNaN(value))
        return value;
    NoFix.log("Extra date parsing needed for " + dateString);
    // JavaScript itself was unable to parse the date, this function will take a little longer
    // Some websites set the date like 30-Nov-1988, whereas it should be 30 Nov 1988
    dateString = dateString.replace(/-/gi,' ');
    dateString = dateString.replace(/GMT /, 'GMT-');// Undo the replacement for GMT (my regex-fu is not that great)
    value = Date.parse(dateString);
    NoFix.log("Newly parsed: " + dateString);
    if (!isNaN(value))
        return value;
    // If all fails, make the cookie persistent for a month (this is a compromise)
    NoFix.log("Parsing of date "+dateString+" failed, making it valid for a month.", 1);
    var now = new Date();
    return now.getTime() + 30*24*60*60*1000;
}

NoFix.extract_expiration_date = function(cookie)
{ // Returns the expiration date as epoch time
    var dateMatch = /expires=([^;]+)/i.exec(cookie);
    if (dateMatch != null && dateMatch[1] != null) {
        return NoFix.parse_date(dateMatch[1]);
    } else {
        return null;
    }
}

NoFix.extract_cookie_domain = function(cookie)
{ // Searches for a domain in the cookie
    var cookiedomain = /domain=([^;]+)/i.exec(cookie);
    if (cookiedomain != null && cookiedomain[1] != null) { // domain is set in cookie
        // trim '.'
        return cookiedomain[1].replace(/^[.]/,'');
    } else {
        return null;
    }
}

NoFix.relative_entropy = function(string)
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

NoFix.encoding_size_score = function(string)
{ // Returns the number of bits that would be neede to encode the string
  // Adapted from Wannes Meert's randomness.py
  // This function is used for calculating whether a string is possibly a session cookie
    // Number of characters in the character set up until now
	var charset = 0;
	// Part that is left after a certain number of checks have been performed
	var checkedstring = string;
	
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

NoFix.is_session_cookie = function(cookieName, cookieValue)
{ // Checks whether the cookie is a session cookie
  // This code was adapted from code found in SessionShield by Nick Nikiforakis
    cookieName = cookieName.toLowerCase();
    
    // Make an exception for web analysis (e.g. Google's analytics) cookies
    // because they are set via JavaScript and fetched via HTTP
    if (/^__utm[abczvkx]/.exec(cookieName)) {
        return false;
    }
    // Check if the cookie is a well-known *non*-SID name
    const known_not_sid = ['locale','skin','fontsize','x-referer','pref','act','presence'];
    for (i in known_not_sid) {
        if (cookieName == known_not_sid[i])
            return false;
    }
    
    // Check if the cookie name is a well-known SID name
    const known_sid = ['phpsessid','aspsessionid', 'asp.net_sessionid', 'jspsessionid', 'jsessionid'];
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
    if ((0.5*NoFix.relative_entropy(cookieValue) + NoFix.encoding_size_score(cookieValue)) >= 0.72)
        return true;
    // If the previous tests failed, treat the cookie as not containing a SID
    return false;
}

NoFix.add_cookie = function(domain, cookie)
{ // Extracts the necessary information from the cookie and adds it to the database
    NoFix.cookiesetcount++;
    var split1 = cookie.indexOf('=');
    var split2 = cookie.indexOf(';');
    if (split2 == -1) // Cookie didn't end in ';'
    	split2 = cookie.length;
    if (split2 <= split1) {
    	NoFix.log("Probably an evil cookie from " + domain + ": " + cookie, 1);
    	return false;
    }
    var cookieName = cookie.substring(0, split1);
    var cookieValue = cookie.substring(split1+1, split2);
    if (NoFix.prefManager.getBoolPref("extensions.nofix.sessidonly") && !NoFix.is_session_cookie(cookieName, cookieValue)) {
        return false; // Only add session cookies
    }
    var expirationDate = NoFix.extract_expiration_date(cookie);
    NoFix.log("Cookie being set: " + cookie + " for domain " + domain);
    return NoFix.db_add_cookie(domain, cookieName, cookieValue, expirationDate);
}

NoFix.handle_new_cookie = function(cookie, requestdomain)
{ // Allows for asynchronous handling of new cookies
	// Search for a domain in the cookie itself (to be able to set cookies for a parent domain)
	cookiedomain = NoFix.extract_cookie_domain(cookie);
    if (cookiedomain == null)
        cookiedomain = requestdomain;
    else { // Check whether the parent domain dictated by the cookie is valid
        // The second part of this if-test will almost never be the case (it never occured while testing the plugin), so we let lazy evaluation do its work
        if (!NoFix.is_subdomain(requestdomain, cookiedomain) && !NoFix.is_subdomain(cookiedomain, requestdomain)) {
            NoFix.log("Probably an evil domain (" + requestdomain + ") trying to set a cookie: " + cookie, 1);
            return false;
        } else
        	// Log this subdomain setting for statistical purposes
        	NoFix.log_subdomain_cookie(cookiedomain, requestdomain);
    }
    // Everything went well, now it's time to add the cookie to our database.
    // The reason we add the cookie regardless of whether it's a session
    // cookie is that later adaptations/configuration settings might need
    // the cookie anyhow.
    return NoFix.add_cookie(cookiedomain, cookie);
}

NoFix.cookie_is_allowed = function(domain, cookieName, cookieValue)
{ // Checks whether the cookie can pass
	// Check if it is in our database
	if (NoFix.db_cookie_is_valid(domain, cookieName, cookieValue))
		return true; // Cookie is in the cookie database
    else if (NoFix.prefManager.getBoolPref("extensions.nofix.sessidonly") && !NoFix.is_session_cookie(cookieName, cookieValue))
        return true; // Only block session cookies
    // Cookie is a session cookie, and is not in our database
    else
    	return false;
}

NoFix.httpRequestObserver =
{   // Called whenever a HTTP request is sent
    observe: function(subject, topic, data) 
    {
        if (topic != "http-on-modify-request") {
            NoFix.log("Not a HTTP request, while httpRequestObserver was called: " + subject + ", " + topic, 0.5);
            return;
        }
        NoFix.nrequests++;
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
        NoFix.ncookierequests++;
        var start = new Date();
        var newCookie = "";
        var cookies = originalCookie.split(";");
        for (i in cookies) {
        	NoFix.nsinglerequests++;
        	single_start = new Date();
            var cookie = cookies[i];
            // Clean up the cookie, strip whitespace
            cookie = cookie.replace(/^\s/,'').replace(/\s$/,'');
            cookieData = cookie.split('=');
            var cookieName = cookieData[0];
            var cookieValue = cookieData.slice(1).join('=');
            if (NoFix.cookie_is_allowed(domain, cookieName, cookieValue)) {
                newCookie += cookie + ';';
                NoFix.log ("Cookie passed: " + cookie + " for domain " + domain, 0.5);
                NoFix.log_file_UI(cookieName, domain, true);
            } else {
                NoFix.log("Cookie was blocked: " + cookie + " for domain " + domain, 1);
                NoFix.log_file_UI(cookieName, domain, false);
            }
            single_end = new Date();
            NoFix.singleRequestDelays += single_end.getTime() - single_start.getTime()
        }
        httpChannel.setRequestHeader("Cookie", newCookie, false);
        var end = new Date();
        delay = end.getTime() - start.getTime()
        NoFix.requestDelays += delay
        NoFix.log_delay(delay, domain, true);
    }
};

NoFix.httpResponseObserver =
{ // Called whenever a HTTP response is received
    observe: function(subject, topic, data)
    {
        if (topic != "http-on-examine-response") // Not a response
            return;
        NoFix.nresponses++;
        NoFix.log("New response");
        var httpChannel = subject.QueryInterface(Components.interfaces.nsIHttpChannel);
        // Search for cookies being set
        try {
            var cookies = httpChannel.getResponseHeader("Set-Cookie").split('\n');
        } catch (exception) {// No cookies set
            return;
        }
        NoFix.log("Containing cookies");
        var start = new Date();
        // If we got this far, cookies were found
        NoFix.ncookieresponses++;
        // Get the domain where the request came from            remove port
        var requestdomain = httpChannel.getRequestHeader("Host").split(':')[0];
        // This variable will contain a modified response header that treats added cookies as HttpOnly
        var newResponseHeader = ""
        // Iterate over all cookies found
        for (i in cookies) {
            var cookie = cookies[i];
            var added = NoFix.handle_new_cookie(cookies[i], requestdomain);
            if (NoFix.prefManager.getBoolPref("extensions.nofix.preventhijacking")) {
            	// All added (session) cookies should be marked HttpOnly so JavaScript can't access them.
            	// This way, we have Session Hijacking protection as per Nick Nikiforakis' paper.
            	if (added)
            		newResponseHeader += cookie + "; HttpOnly" + "\n";
            	else
            		newResponseHeader += cookie + "\n";
    		}
        }
        if (NoFix.prefManager.getBoolPref("extensions.nofix.preventhijacking")) {
        	httpChannel.setResponseHeader("Set-Cookie", newResponseHeader, false);
    	}
        var end = new Date();
        delay = end.getTime() - start.getTime()
        NoFix.responseDelays += delay
        NoFix.log_delay(delay, requestdomain, false);
    }
};

NoFix.shutdownObserver =
{ // Called when Firefox exits
    observe: function(subject, topic, data)
    {
        NoFix.log ("Shutting down");
        NoFix.db_clean_session(normalDb);
        NoFix.db_drop(privateDb);
        try {
            NoFix.currentDb.close();
            NoFix.log("Database closed");
        } catch (e) {
            NoFix.log ("Could not close database: " +e, 2);
        }
        try {
            NoFix.privateDb.close();
            NoFix.log("Private database closed");
        } catch (e) {
            NoFix.log ("Could not close private database: " +e, 2);
        }
        try {
            NoFix.logFile.close();
        } catch (e) {}
        NoFix.log("Cleanup ready");
    }
}

NoFix.privateBrowsingObserver =
{ // Called on private browsing state change
    observe : function(subject, topic, data) {
        if (data == "enter") {
            NoFix.private_browsing = true;
            // Create the private db table
            NoFix.privateDb = NoFix.db_create("nofix-private");
            NoFix.currentDb = privateDb;
            NoFix.log("Private browsing enabled");
        } else if (data == "exit") {
            NoFix.private_browsing = false;
            // Remove all data from the private db
            NoFix.db_drop();
            // Reset state
            NoFix.currentDb = NoFix.normalDb;
            NoFix.log("Private browsing disabled");
        }
    }
};
/*
 * Plugin initialization starts here
 */
 
// Load preferences
NoFix.prefManager = Components.classes["@mozilla.org/preferences-service;1"]
                                .getService(Components.interfaces.nsIPrefBranch);

// Create the database connection
NoFix.normalDb = NoFix.db_create("nofix");
NoFix.currentDb = NoFix.normalDb;
    
// Open the log file
NoFix.file = Components.classes["@mozilla.org/file/directory_service;1"]  
                  .getService(Components.interfaces.nsIProperties)  
                  .get("ProfD", Components.interfaces.nsIFile);  
NoFix.file.append("nofix.log");
NoFix.logFile = Components.classes["@mozilla.org/network/file-output-stream;1"].createInstance(Components.interfaces.nsIFileOutputStream);
// Append to file
try {
    NoFix.logFile.init(NoFix.file, 0x02 | 0x10, 0666, 0);
} catch(e) { // File does not yet exist, create it
    NoFix.logFile.init(NoFix.file, 0x02 | 0x08 | 0x20, 0666, 0);
}
                      
// Add the observers for HTTP requests
NoFix.observerService = Components.classes["@mozilla.org/observer-service;1"].getService(Components.interfaces.nsIObserverService);
NoFix.observerService.addObserver(NoFix.httpRequestObserver, "http-on-modify-request", false);
NoFix.observerService.addObserver(NoFix.httpResponseObserver, "http-on-examine-response", false);
// Add the observer for application shutdown
NoFix.observerService.addObserver(NoFix.shutdownObserver, "quit-application-requested", false);
// Add the observer for private browsing mode
NoFix.observerService.addObserver(NoFix.privateBrowsingObserver, "private-browsing", false);

// Code used to test the extension
if (NoFix.TEST_PLUGIN) {
	start = new Date();
	var errorstring = ""
	for (a = 0; a < 500; a++) {
		errorstring = "";
		//try {
			const session_cookies = ["phpsessid=20;domain=google.be", "definitely_session=n0p4ssw0rd1sth1s;domain=google.com", "randomythingy=hfvcIjmcJDX9LzdQ", "reddit=4080389%2C2011-02-14T08%3A36%3A21%2C8fe3c8ea18bd2b8a82d1aaac192279d5d8aa6a4d"]
			for (d in session_cookies) {
				cook = session_cookies[d].split('=');
				if (!NoFix.is_session_cookie(cook[0], cook[1])) {
					errorstring += "Not a session cookie: " + session_cookies[d] + "\n"
				}
				NoFix.handle_new_cookie(session_cookies[d], "www.google.be");
			}
			const non_session_cookies = ["locale=eenheelmoeilijkelangetaal", "hi=#0Rt"];
			for (d in non_session_cookies) {
				cook = non_session_cookies[d].split('=');
				if (NoFix.is_session_cookie(cook[0], cook[1]))
					errorstring += "A session cookie: " + non_session_cookies[d] + "\n"
				NoFix.handle_new_cookie(non_session_cookies[d], "www.google.be");
			}
			NoFix.parse_date("30-Nov-1988");
		//} catch (e) {
		//	errorstring += e;
		//}
	}
	end = new Date();
	delay = end.getTime() - start.getTime()
	alert("Delay was: " + delay + "//" + errorstring);
}
// END OF TEMPORARY DEBUG CODE

// All done
NoFix.log("NoFix plugin started");
