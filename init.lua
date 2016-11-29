require 'config'
local match = string.match
local ngxmatch=ngx.re.match
local unescape=ngx.unescape_uri
local optionIsOn = function (options) return options == "on" and true or false end

logpath = logdir 
rulepath = RulePath
UrlDeny = optionIsOn(UrlDeny)
ReferDeny = optionIsOn(ReferDeny)
attacklog = optionIsOn(attacklog)
CCDeny = optionIsOn(CCDeny)

--函数 getClientIp 获取用户IP
function getClientIp()
        IP = ngx.req.get_headers()["clientRealIp"]
        if IP == nil then
                IP  = ngx.var.remote_addr 
        end
        if IP == nil then
                IP  = "unknown"
        end
        return IP
end

--函数 获取servername --
function getServername()
         servername = ngx.var.host
         if servername == nil then
            servername = "unknown"
         end
         return servername
end

--日志模块 --
function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end
function log(hacktype,url,data,ruletag)
    if attacklog then
	    local realIp = getClientIp()
	    local ua = ngx.var.http_user_agent
    	local servername = getServername()
    	local time = ngx.localtime()
	    if ua  then
		    line = realIp.." ["..time.."] \""..hacktype.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
    	else
	    	line = realIp.." ["..time.."] \""..hacktype.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
    	end
	    local filename = logpath..'/'.."hack."..ngx.today()..".log"
        write(filename,line)
    end
end

--规则读取函数--
function read_rule(var)
    file = io.open(rulepath..'/'..var,"r")
    if file==nil then
    	return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end


urlrules=read_rule('url')
uarules=read_rule('user-agent')
referrules=read_rule('refer')


function say_html()
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.say(html)
        ngx.exit(200)
    end
end

-- url 处理函数 --

function url()
    if UrlDeny then
        for _,rule in pairs(urlrules) do
            if rule ~="" and ngxmatch(ngx.var.request_uri,rule,"isjo") then
                log('HACK-GET',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end

--refer处理函数 --

function refer()
    local refer = ngx.var.http_referer
    if ReferDeny and refer then
        for _,rule in pairs(referrules) do
            if rule ~="" and ngxmatch(refer,rule,"isjo") then
                log('HACK-REFER',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end

-- ua 处理函数 --
function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
	    for _,rule in pairs(uarules) do
	        if rule ~="" and ngxmatch(ua,rule,"isjo") then
	            log('HACK-UA',ngx.var.request_uri,"-",rule)
	            say_html()
	        return true
	        end
	    end
    end
    return false
end

-- 放刷函数，--
function denycc()
    if CCDeny then
    	local uri=ngx.var.uri
        CCcount=tonumber(string.match(CCrate,'(.*)/'))
        CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        local token = getClientIp()..uri
        local limit = ngx.shared.limit
        local req,_=limit:get(token)
        if req then
            if req > CCcount then
                 ngx.exit(503)
                return true
            else
                 limit:incr(token,1)
            end
        else
            limit:set(token,1,CCseconds)
        end
    end
    return false
end

--函数 whiteip 白名单，调用getClientIp函数--

function whiteip()
    if next(ipWhitelist) ~= nil then
        for _,ip in pairs(ipWhitelist) do
            if getClientIp()==ip then
                return true
            end
        end
    end
        return false
end

---函数 blockip 黑名单 ， 调用getClientIp函数---

function blockip()
     if next(ipBlocklist) ~= nil then
         for _,ip in pairs(ipBlocklist) do
             if getClientIp()==ip then
                 ngx.exit(403)
                 return true
             end
         end
     end
         return false
end

-- 函数  whitehost --

function whitehost()
    if next(HostWhitelist) ~= nil then
        for _,host in pairs(HostWhitelist) do
             if getServername()==host then
                 return true
             end
        end
    end
        return false
end
