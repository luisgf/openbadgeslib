# Rewrite checksumPolicy=fail -> ignore only inside the danubetech-public
# <repository> block. DanubeTech's Nexus serves the jars but no .sha1/.md5
# companions, so Maven 3.9+ otherwise aborts with
# "Checksum validation failed, no checksums available".
BEGIN { in_repo = 0; buf = "" }
/<repository>/ {
    in_repo = 1
    buf = $0
    next
}
in_repo {
    buf = buf "\n" $0
    if ($0 ~ /<\/repository>/) {
        if (buf ~ /<id>danubetech-public<\/id>/) {
            gsub(/<checksumPolicy>fail<\/checksumPolicy>/, \
                 "<checksumPolicy>ignore</checksumPolicy>", buf)
        }
        print buf
        buf = ""
        in_repo = 0
    }
    next
}
{ print }
