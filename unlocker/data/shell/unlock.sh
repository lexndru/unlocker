# define exit errors constants
SUCCESS=0
FAILURE=1
RESTART_ONCE=2
ERROR_BAD_CALL=100
ERROR_MISSING_DEPS=101
ERROR_EMPTY_FILE=102
ERROR_JUNK_FILE=103
ERROR_NO_SECRETS=104
ERROR_CANNOT_DECRYPT=106
ERROR_CANNOT_CREATE=107
ERROR_UNSUPPORTED_SCHEME=108
ERROR_RACE_COND=110
ERROR_BAD_ARGUMENTS=120

# supported protocols
SUPPORTED_PROTOCOLS="ssh http https redis mysql psql mongo"

# set highest debug level available
if [ "x$DEBUG" = "xtrue" ]; then
    set -x
fi

# unlock servers wrapper
unlock_server() {

    # preparing to connect user to server
    console "Establishing connection to $SERVER ..."

    # detect connection protocol and call proper unlock method
    case $SCHEME in

        # handle HTTP(s) servers
        http|https) {
            if ! is_installed curl; then
                require_deps curl
            fi
            local args="-u ${USER}:${PASSKEY}"
            if [ ! -z "$DEBUG" ]; then
                args="$args -v"
            fi
            curl ${SCHEME}://${HOST}:${PORT} $args
        }
        ;;

        # handle Redis servers
        redis) {
            if ! is_installed redis-cli; then
                require_deps redis
            fi
            if [ ! -z "$DEBUG" ]; then
                console "No debug output for Redis"
            fi
            redis-cli -h $HOST -p $PORT -a $PASSKEY
        }
        ;;

        # handle MongoDB servers
        mongo) {
            if ! is_installed mongo; then
                require_deps mongodb-org
            fi
            if [ ! -z "$DEBUG" ]; then
                console "No debug output for MongoDB"
            fi
            mongo --username $USER --password $PASSKEY --host $HOST --port $PORT
        }
        ;;

        # handle PostgreSQL servers
        psql) {
            if ! is_installed psql; then
                require_deps postgresql
            fi
            if [ ! -z "$DEBUG" ]; then
                console "No debug output for PostgreSQL"
            fi
            export PGPASSWORD="$PASSKEY"
            psql -h $HOST -p $PORT -U $USER
            unset PGPASSWORD
        }
        ;;

        # handle MySQL servers
        mysql) {
            if ! is_installed mysql; then
                require_deps mysql-client
            fi
            local args="-h $HOST -p$PASSKEY -P $PORT -u $USER"
            if [ ! -z "$DEBUG" ]; then
                args="$args -v"
            fi
            mysql --reconnect $args
        }
        ;;

        # handle SSH servers
        ssh) {
            case $AUTH in
                password) {
                    if ! is_installed sshpass; then
                        require_deps sshpass
                    fi
                    export SSHPASS="$PASSKEY"
                    local verbose=""
                    if [ ! -z "$DEBUG" ]; then
                        verbose="-v "
                    fi
                    sshpass ${verbose}-e ssh "${USER}@${HOST}" -P ${PORT}
                    unset SSHPASS
                }
                ;;
                privatekey) {
                    if ! is_installed ssh; then
                        require_deps openssh-server
                    fi
                    local kf="$TEMP_DIRECTORY/$(date +%s).key"
                    echo "$PASSKEY" > "$kf"
                    local args="-i ${kf} -p${PORT}"
                    if [ ! -z "$DEBUG" ]; then
                        args="$args -v"
                    fi
                    ssh "${USER}@${HOST}" $args
                }
                ;;
                *) {
                    echo "Unsuported authentification method \"$AUTH\" on $SCHEME"
                    close $ERROR_BAD_CALL
                }
                ;;
            esac
        }
        ;;

        # unsupported protocol
        *) {
            console err "Cannot unlock $SERVER because \"$SCHEME\" is not supported"
            close $ERROR_UNSUPPORTED_SCHEME
        }
        ;;

    esac

    # used is now disconected
    console "Successfully closed connection to $SERVER..."
}

# decrypt secrets
decrypt_secrets() {
    if ! is_installed gpg; then
        console err "Cannot decrypt secrets because some dependencies are missing:"
        console err "\"gpg\" is NOT installed! Please install \"gpg\" and try again"
        close $ERROR_MISSING_DEPS
    fi

    # decrypt secrets and delete the encrypted file
    gpg -o "$SECRETS" --decrypt "$LOCKED_SECRETS"

    # get exit code of decryption and don't delete the encrypted file if it failed
    if [ "$?" != "0" ]; then
        console err "Failed to decrypt secrets..."
        console "Closing..."
        close $ERROR_CANNOT_DECRYPT
    else
        rm -f "$LOCKED_SECRETS"  # it still outputs errors if any
        console "Successfully decrypted..."
        return $SUCCESS
    fi
    return $FAILURE
}

if [ -z "$1" ] && [ "$(ls -l "$LOCKED_SECRETS" 2> /dev/null | wc -l)" = "1" ]; then
    decrypt_secrets && close $RESTART_ONCE
fi

# output a help message
if [ "x$1" = "xhelp" -o "x$1" = "x" ]; then
    echo "              _            _             "
    echo "  _   _ _ __ | | ___   ___| | _____ _ __ "
    echo " | | | | '_ \| |/ _ \ / __| |/ / _ \ '__|"
    echo " | |_| | | | | | (_) | (__|   <  __/ |   "
    echo "  \__,_|_| |_|_|\___/ \___|_|\_\___|_|   "
    echo ""
    echo "Unlocker v$VERSION $(uname -op)"
    echo ""
    echo "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR"
    echo "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,"
    echo "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE"
    echo "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER"
    echo "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,"
    echo "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE"
    echo "SOFTWARE."
    echo ""
    echo "  Please report bugs at $HOMEPAGE"
    echo ""
    echo "Usage:"
    echo "  service [user@]host[:port]  - Unlock server if credentials are known"
    echo ""
    echo "Service:"
    echo "  $SUPPORTED_PROTOCOLS"
    echo ""
    echo "Examples:"
    echo "  redis 127.0.0.1:6379        - Connect to local Redis with an available user"
    echo "  mysql 127.0.0.1             - Connect to MySQL with any available user"
    echo "  mysql guest@database:3306   - Connect to MySQL on port 3306 with user guest"
    echo "  ssh root@yourserver.tld     - Connect to yourserver.tld with root user"
    echo "  ssh yourserver.tld          - Connect to yourserver.tld with available user"
    echo ""
    exit 0
fi

# check if all arguments are provided
if [ -z "$2" ]; then
    echo "Required arguments are missing: see \"unlock help\" for examples" && exit 1
fi

# check if the HOME variable is missing
if [ -z "$HOME" ]; then
    echo "Cannot find your user's home directory..." && exit 1
fi

# dependency list
DEPENDENCIES="unlocker python tail cat wc grep sed tr cut tee touch mkdir ls mv rm"

# set path to secrets
SECRETS="$HOME/.unlocker/.secrets"

# set path to encrypted secrets (same directory, different filename)
LOCKED_SECRETS="$SECRETS.lock"

# save current working directory
THIS_DIRECTORY=$(pwd)

# path to temporary directory
TEMP_DIRECTORY=/tmp/.unlocker

# unlocker all records
UNLOCKER_TABLE=""
UNLOCKER_LIST=""
UNLOCKER_LAN=""

# service holder
SCHEME=""

# server address holder
SERVER=""

# passkey holder
PASSKEY=""

# authentification method
AUTH=""

# server username
USER=""

# server hostname
HOST=""

# server port
PORT=""

# server alias name
NAME=""

# credentials
CREDENTIALS="SCHEME SERVER AUTH USER HOST PORT NAME PASSKEY"

# positional parameters
POS_SIGN=1
POS_JUMP=2
POS_SCHEME=3
POS_IPv4=4
POS_PORT=5
POS_HOST=6
POS_USER=7
POS_NAME=8

# detect port for service
autodetect_port() {
    case $SCHEME in
        http)       PORT=80     ;;
        https)      PORT=443    ;;
        redis)      PORT=3306   ;;
        kafka)      PORT=9092   ;;
        mongo)      PORT=27017  ;;
        neo4j)      PORT=7474   ;;
        mysql)      PORT=3306   ;;
        psql)       PORT=5432   ;;
        smtp)       PORT=25     ;;
        ssh)        PORT=22     ;;
        ftp)        PORT=21     ;;
        rsync)      PORT=873    ;;
    esac
}

# output wrapper
console() {
    if [ $# -eq 2 ] && [ "x$1" = "xerr" ]; then
        shift
        echo "$1" 1>&2
    elif [ ! -z "$DEBUG" ]; then
        echo "$1"
    fi
}

# clean close with error code
close() {
    local EXIT_CODE=0
    if [ $# -eq 1 ]; then
        EXIT_CODE=$1
    fi
    console "Closed"
    exit $EXIT_CODE
}

# output an error with missing dependency
require_deps() {
    if [ $# -eq 0 ]; then
        console err "Cannot yield missing dependencies without a list of dependencies"
        close $ERROR_BAD_CALL
    fi
    console err "Notice: You're connecting to a $SCHEME server ($SERVER) with a $AUTH"
    console err "Notice: The following packages are required in order to continue:"
    local count=0
    for dep in $@; do
        count=$(expr $count + 1)
        console err " ${count}) $dep"
    done
    console err "Please install the packages listed above and try again"
    close $ERROR_MISSING_DEPS
}

# check if file exists or not
file_exists() {
    if [ -z "$1" ]; then
        close $ERROR_BAD_CALL
    fi
    local EXISTS=$(ls -l "$1" 2> /dev/null | wc -l)
    if [ "$EXISTS" = "0" ]; then
        return $FAILURE
    fi
    return $SUCCESS
}

# check if dependency is installed
is_installed() {
    if [ -x "$(command -v $1)" ]; then
        return $SUCCESS
    fi
    return $FAILURE
}

# create temporary unlocker file storage
initialize() {

    # update unlocker servers table
    UNLOCKER_TABLE="$(unlocker list)"
    UNLOCKER_LIST="$(echo "$UNLOCKER_TABLE" | tail -n +3)"
    if [ "$?" != "0" ]; then
        console err "Cannot refresh credentials list"
    else
        console "Credentials list refreshed ..."
    fi

    # create temporary directory
    if file_exists "$TEMP_DIRECTORY"; then
        console "Temporary directory already exists"
    else
        mkdir -p "$TEMP_DIRECTORY"
        if [ "$?" = "0" ]; then
            console "Created temporary directory"
        else
            console err "Cannot create temporary directory"
            close $ERROR_CANNOT_CREATE
        fi
    fi

    return $SUCCESS
}

# clean temporary directory
cleanup() {
    rm -rf "$TEMP_DIRECTORY"
    if [ "$?" = "0" ]; then
        console "Removed temporary directory"
    else
        console err "Cannot remove temporary directory"
        console err "You should remove it manually: $TEMP_DIRECTORY"
    fi
    return $SUCCESS
}

# cleanup on trap
safe_cleanup() {
    console "Preparing cleanup..."
    cleanup
    console "Closing now..."
    close $SUCCESS
}

# save passkey into holder
save_passkey() {
    if [ ! -z "$DEBUG" ]; then
        PASSKEY=$(echo "$@" | unlocker)
    else
        PASSKEY=$(echo "$@" | unlocker 2> /dev/null) # TODO: can it be done better?
    fi

    # check if unlocker had an ok exit code and we got a passkey...
    if [ "$?" = "0" ] && [ ! -z "$PASSKEY" ]; then
        console "Got passkey..."
        local pass="$(echo "$PASSKEY" | tr '\n' ' ')"

        # decode actual passkey
        PASSKEY=$(echo "$pass" | cut -d " " -f2 | python -m base64 -d)
        if [ "$?" != "0" ]; then
            console err "Failed to extract secrets from passkey..."
            return $FAILURE
        fi

        # detect authentification method used for passkey
        AUTH=$(echo "$pass" | cut -d " " -f1)
        if [ "$?" != "0" ]; then
            console err "Failed to extract authentification from passkey..."
            return $FAILURE
        fi

        # successfully saved passkey and auth method
        return $SUCCESS
    fi

    # failed to get a passkey...
    echo "Unable to get passkey..."
    return $FAILURE
}

# extract param from given record
read_param() {
    if [ $# -eq 2 ]; then
        echo "$1" | cut -d "|" -f$2 | tr -d " "
        if [ "$?" != "0" ]; then
            console err "Cannot get record param $2 for $1 ..."
        fi
    else
        console err "Not enough input arguments to return record param"
    fi
}

# go through all records and filter input
query_unlocker() {
    local all="false"

    # check if query all is required
    if [ ! -z "$3" ]; then
        shift
        all="true"
    fi
    local pos=$2

    # exit if input is missing
    if ! [ $# -eq 2 ]; then
        console err "Not all required arguments are provided to query unlocker"
    fi

    # loop all known servers
    echo "$UNLOCKER_LIST" | grep "$1" | while read line; do
        local name="$(read_param "$line" $pos)"
        if [ "x$name" = "x$1" ]; then
            echo $line
            if [ "x$all" != "xtrue" ]; then
                break
            fi
        fi
    done
}

# check if provided argument is an alias of a server instead of an address
scan_server_alias() {
    local scheme

    # exit if address is missing
    if [ -z "$1" ]; then
        console err "Cannot check alias if no address is provided"
        close $ERROR_BAD_CALL
    fi

    # go through all records and check if alias name exists
    local record="$(query_unlocker "$1" $POS_NAME)"

    # check is name is set and return exit code
    if [ -z "$record" ]; then
        console "Unable to find server alias for $1 ..."
        return $FAILURE
    fi

    # get all missing variables
    NAME=$(read_param "$record" $POS_NAME)
    HOST=$(read_param "$record" $POS_HOST)
    USER=$(read_param "$record" $POS_USER)
    PORT=$(read_param "$record" $POS_PORT)

    # validate scheme and try to correct ...
    scheme=$(read_param "$record" $POS_SCHEME)
    if [ "x$scheme" != "x$SCHEME" ]; then
        console err "You requested $SCHEME, but only $scheme is available for this server"
        read -p "Switch to $scheme? [yN] " switch
        case $switch in
            y) {
                console "Switching from $SCHEME to $scheme ..."
                SCHEME=$scheme
            }
            ;;
            *) {
                console "Not switching ..."
            }
        esac
    fi

    return $SUCCESS
}

# try to find credentials for server address
scan_server_address() {

    # exit if address is missing
    if [ -z "$1" ]; then
        console err "Cannot check credentials if no address is provided"
        close $ERROR_BAD_CALL
    fi

    # check for user, host and port
    local creds="$(echo "$1" | sed -En 's/([a-zA-Z0-9_]+)@([a-zA-Z][a-zA-Z0-9\-\.]+):([0-9]+)/\1 \2 \3/gp')"
    if [ ! -z "$creds" ]; then
        USER=$(echo "$creds" | cut -d " " -f1)
        HOST=$(echo "$creds" | cut -d " " -f2)
        PORT=$(echo "$creds" | cut -d " " -f3)
    else
        # unable to find all three... check for each of the two user-host and host-port
        # check for user and host
        creds="$(echo "$1" | sed -En 's/([a-zA-Z0-9_]+)@([a-zA-Z][a-zA-Z0-9\-\.]+)/\1 \2/gp')"
        if [ ! -z "$creds" ]; then
            USER=$(echo "$creds" | cut -d " " -f1)
            HOST=$(echo "$creds" | cut -d " " -f2)
            local port="$(echo "$UNLOCKER_LIST" | grep "$SCHEME .* $HOST .* $USER")"
            if [ -z "$port" ] || [ "$(echo "$port" | wc -l)" = "0" ]; then
                console err "Cannot find port for address ${SCHEME}://${USER}@${HOST}"
                return $FAILURE
            fi
            PORT="$(read_param "$port" $POS_PORT | tr '\n' ' ' | cut -d " " -f1)"
        else
            # unable to find user-host ... there's only one option left
            # check for host and port
            creds="$(echo "$1" | sed -En 's/([a-zA-Z][a-zA-Z0-9\-\.]+):([0-9]+)/\1 \2/gp')"
            if [ ! -z "$creds" ]; then
                HOST=$(echo "$creds" | cut -d " " -f1)
                PORT=$(echo "$creds" | cut -d " " -f2)
                local user="$(echo "$UNLOCKER_LIST" | grep "$SCHEME .* $PORT .* $HOST")"
                if [ -z "$user" ] || [ "$(echo "$user" | wc -l)" = "0" ]; then
                    console err "Cannot find user for address ${SCHEME}://${HOST}:${PORT}"
                    return $FAILURE
                fi
                for username in $(read_param "$user" $POS_USER | tr '\n' ' '); do
                    if [ "x$username" != "xroot" ]; then
                        USER=$username
                        break
                    fi
                done
                if [ -z "$USER" ]; then
                    USER="$(read_param "$user" $POS_USER | tr '\n' ' ' | cut -d " " -f1)"
                fi
                console "Using $USER to connect to server ${SCHEME}://${HOST}:${PORT}"
            else
                # nothing else to parse... it has to be the host
                HOST=$1
                local rest="$(echo "$UNLOCKER_LIST" | grep "$SCHEME .* $HOST")"
                if [ -z "$rest" ] || [ "$(echo "$rest" | wc -l)" = "0" ]; then
                    console err "Cannot find credentials for ${SCHEME}://${HOST}"
                    return $FAILURE
                fi
                for username in $(read_param "$rest" $POS_USER | tr '\n' ' '); do
                    if [ "x$username" != "xroot" ]; then
                        USER=$username
                        break
                    fi
                done
                if [ -z "$USER" ]; then
                    USER="$(read_param "$rest" $POS_USER | tr '\n' ' ' | cut -d " " -f1)"
                fi
                local port="$(echo "$UNLOCKER_LIST" | grep "$SCHEME .* $HOST .* $USER")"
                if [ -z "$port" ] || [ "$(echo "$port" | wc -l)" = "0" ]; then
                    console err "Cannot find port for address ${SCHEME}://${USER}@${HOST}"
                    return $FAILURE
                fi
                PORT="$(read_param "$port" $POS_PORT | tr '\n' ' ' | cut -d " " -f1)"
            fi
        fi # inner if
    fi # main if

    # double check if address is complete
    local addr="${SCHEME}://${USER}@${HOST}:${PORT}"
    if [ -z "$SCHEME" ] || [ -z "$USER" ] || [ -z "$HOST" ] || [ -z "$PORT" ]; then
        console err "Incomplete server address ..."
        console err "Address: $addr"
        return $FAILURE
    else
        console "Preparing address $addr ..."
    fi

    # find the server alias
    local record="$(echo "$UNLOCKER_LIST" | grep "$SCHEME .* $PORT .* $HOST .* $USER")"
    local total="$(echo "$record" | wc -l)"

    if [ "$total" = "0" ]; then
        # altough this shouldn't happen since we got this far... better handle it
        console err "Server name not found for address $addr ..."
        return $FAILURE
    elif [ "$total" != "1" ]; then
        # more than one alias means conflict... user does not respect documentation :(
        console err "Server address found under more than one name..."
        local default
        local number=0
        for name in $(read_param "$record" $POS_NAME); do
            number="$(expr $number + 1)"
            console err " ${number}) $name"
            default=$name  # keep last
        done
        read -p "Which one to use? Type name [$default]: " NAME
        if [ -z "$NAME" ]; then
            NAME=$default
        fi
        console "Using $NAME for $addr ..."
    else
        # get whatever alias is available
        NAME=$(read_param "$record" $POS_NAME)
    fi

    # feedback confirmation with address and alias
    console "Saving name for $addr as $NAME"

    return $SUCCESS
}

# match server address or name from keychain
find_server_address_or_name() {
    local warning

    # review known servers in debug mode
    console "Printing unlockable servers table...\n$UNLOCKER_TABLE"

    # exit if input is missing
    if [ -z "$1" ]; then
        console err "Cannot check alias name or server address if no input is provided"
        close $ERROR_BAD_CALL
    fi

    # autodetect server nature and get credentials if found...
    if scan_server_alias "$1"; then

        # test input as an alias
        console "Found server alias..."
        if [ -z "$NAME" ] || ! save_passkey "$NAME"; then
            console err "Cannot continue without a passkey or an invalid name"
            close $ERROR_NO_SECRETS
        fi

        # notify user about production servers...
        local tag="$(echo "$1" | sed -En 's/([a-zA-Z]+):([a-zA-Z][a-zA-Z0-9\-\.\_]+)/\1/gp')"
        case $tag in
            live|prod) {
                echo "Notice: Production server ahead!"
                echo "Notice: You are connecting to a LIVE production server..."
                echo "Notice: Proceed with caution"
                warning="true"
            }
            ;;
        esac

        console "Ready to connect to server alias $1..."

    elif scan_server_address "$1"; then

        # test input as an address
        console "Found server address..."
        local addr="${SCHEME}://${USER}@${HOST}:${PORT}"
        if ! save_passkey "$addr"; then
            console err "Cannot continue without a passkey or an invalid address"
            close $ERROR_NO_SECRETS
        fi

        # notify user about root user connection ...
        if [ "x$USER" = "xroot" ]; then
            echo "Notice: Root user ahead!"
            echo "Notice: You are connecting to a server with ROOT privileges..."
            echo "Notice: Proceed with caution"
            warning="true"
        fi

        console "Ready to connect to server address $1..."

    else

        # unsuported input or maybe unlocker just doesn't have the keys yet...
        read -p "Press any key to add new server or ^C to exit ... " anykey
        echo "Notice: You can use an underscore character for unnecessary fields"
        echo "Notice: Preparing to add new \"${SCHEME}\" server..."

        # get default host from parse results
        read -p "Type host [$HOST]: " host
        if [ ! -z "$host" ]; then
            HOST=$host
        fi

        # get user if parsed...
        read -p "Type user [$USER]: " user
        if [ ! -z "$user" ]; then
            USER=$user
        fi

        # get port if parsed or try to display default ports by schema
        if [ -z "$PORT" ] && ! autodetect_port; then
            console "Cannot detect port for service $SCHEME ..."
        fi
        read -p "Type port [$PORT]: " port
        if [ ! -z "$port" ]; then
            PORT=$port
        fi

        # some services do not support private keys ...
        while true; do
            echo "Do you have a password or a private key?"
            echo " 1) I have a password"
            echo " 2) I have a private key"
            echo " 3) I don't have any of these"
            read -p "Type answer (number): " auth
            if [ -z "$auth" ]; then
                echo "Cannot undersand answer. Try again..."
            else
                case $auth in
                    1) {
                        AUTH="password"
                        break
                    }
                    ;;
                    2) {
                        AUTH="privatekey"
                        break
                    }
                    ;;
                    3) {
                        echo "Find a password or a private key and try again"
                        return $FAILURE
                    }
                    ;;
                    *) {
                        echo "Cannot undersand answer. Try again..."
                    }
                    ;;
                esac
            fi
        done

        # handle authentification failure
        if [ -z "$AUTH" ]; then
            console err "Missing authentification method. Abort..."
            close $ERROR_BAD_ARGUMENTS
        fi

        # inform user what's about to happen ...
        echo "Notice: You'll be asked for a $AUTH after you finish server setup"
        echo "Notice: Providing an invalid $AUTH will break the setup"
        NAME="$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 10)"
        read -p "Type friendly name [$NAME]: " name
        if [ ! -z "$name" ]; then
            NAME=$name
        fi

        local bounce
        while true; do
            read -p "Is this server directly reachable? [Yn] " answer
            if [ -z "$answer" ]; then
                bounce="no"
                break
            else
                case $answer in
                    y) {
                        bounce="no"
                        break
                    }
                    ;;
                    n) {
                        bounce="yes"
                        break
                    }
                    ;;
                    *) {
                        echo "Cannot undersand answer. Try again..."
                    }
                    ;;
                esac
            fi
        done

        local jump
        if [ "x$bounce" = "xyes" ]; then
            echo "Please select jump server from the list below"
            echo "Leave it blank to skip jump server..."
            echo "$UNLOCKER_TABLE"
            read -p "Type jump server (HASH): " jump
        fi

        local arguments="-a $AUTH -s $SCHEME -h $HOST -p $PORT -u $USER -n $NAME"
        if [ ! -z "$jump" ]; then
            arguments="$arguments -j $jump"
        fi

        echo "Saving server ${SCHEME}://${USER}@${HOST}:${PORT} (${NAME}) with ${AUTH} ..."
        unlocker append $arguments
        if [ "$?" != "0" ]; then
            # handle any bad exit on save
            console err "Cannot find a supported unlock method"
            console err "Please consult the help guide for \"${SCHEME}\" connections"
            console err "Report bugs at ${HOMEPAGE} if you consider to be the case"
        fi

        return $RESTART_ONCE
    fi

    # inform user what's about to happen
    echo "Connecting to \033[92m${SCHEME}://${USER}@${HOST}:${PORT}\033[0m ($NAME) using \033[92m${AUTH}\033[0m"

    # confirm with user the connection (special cases only)
    if [ "x$warning" = "xtrue" ]; then
        echo "Press any key to continue or ^C to exit..."
        read -p "" _
    fi

    return $SUCCESS
}

# unlock secrets if not already locked
unlock_secrets() {
    local found_secrets="false"

    # check if secrets are already unlocked
    if file_exists "$SECRETS"; then
        found_secrets="true"
    fi

    # check if secrets are locked anyway
    if file_exists "$LOCKED_SECRETS"; then

        # resolve conflict ...
        if [ "x$found_secrets" = "xtrue" ]; then
            echo "Notice: Found both plain secrets and encrypted secrets! Choose how to continue"
            echo " 1) Move encrypted secrets file to current directory and use plain secrets"
            echo " 2) Use plain secrets and delete encrypted secrets file"
            echo " 3) Decrypt secrets file and overwrite plain secrets"
            echo " 4) Move plain secrets to current directory and decrypt secrets"
            echo " 5) Exit"
            while true; do
                read -p "Type number: " answer
                case $answer in

                    # not the best idea ... what is that file was put there in other
                    # ways? should check for a checksum at least
                    1) {
                        mv "$LOCKED_SECRETS" "$THIS_DIRECTORY/encrypted_secrets"
                        if [ "$?" = "0" ]; then
                            echo "Moved encrypted file to current directory..."
                            break
                        else
                            echo "Failed to move encrypted file to current directory"
                        fi
                    }
                    ;;

                    # only for those that know what they are doing ...
                    2) {
                        rm -f "$LOCKED_SECRETS"
                        if [ "$?" = "0" ]; then
                            echo "Removed encrypted file..."
                            break
                        else
                            echo "Failed to remove encrypted file"
                        fi
                    }
                    ;;

                    # should I make this a default option? its the safest one
                    # since you decrypt something you know it's your own
                    3) {
                        if decrypt_secrets; then
                            break
                        else
                            echo "Cannot decrypt secrets..."
                        fi
                    }
                    ;;

                    # keep old plain secrets for analysis or something, maybe there
                    # are old credentials you migh want to keep...
                    4) {
                        mv "$SECRETS" "$THIS_DIRECTORY/plain_secrets"
                        if [ "$?" = "0" ]; then
                            echo "Moved plain secrets file to current directory..."
                            if decrypt_secrets; then
                                break
                            else
                                echo "Cannot decrypt secrets..."
                            fi
                        else
                            echo "Failed to move plain secrets file to current directory"
                        fi
                    }
                    ;;

                    # better safe than sorry
                    5) {
                        echo "Preparing to close..."
                        close $SUCCESS
                    }
                    ;;

                    # fallback ... loop
                    *) {
                        echo "Cannot understand answer... Try again with"
                    }
                    ;;
                esac
            done

        # there is only one encrypted file with secrets...
        else

            # normal flow continues here
            if ! decrypt_secrets; then
                console err "Cannot decrypt secrets..."
                console "Preparing to close..."
                close $ERROR_CANNOT_DECRYPT
            fi

        fi # inner conflict
    fi # ending the locked secrets block

    # let the user know that the secrets are now unlocked
    console "Found secrets..."
}

# handle setup and warm up
bootstrap() {
    trap safe_cleanup 2 3

    # check if all needed dependencies are installed
    for app in $DEPENDENCIES; do
        if ! is_installed $app; then
            console err "Missing dependency \"$app\" ..."
            console err "Please install $app and try again"
            close $ERROR_MISSING_DEPS
        fi
    done

    # autodetect secrets file and decrypt if needed
    unlock_secrets

    # double check if secrets file exist
    if ! file_exists "$SECRETS"; then
        console err "Warning: Cannot find secrets on this system"
        console "Warning: Either unlocker has not been initialized, either secrets are missing"
        console "Warning: Preparing to close..."
        close $ERROR_RACE_COND
    fi

    # prepare to unlock
    if ! initialize; then
        console err "Cannot initialize script..."
        close $ERROR_BAD_CALL
    fi

    # trying to find if requested servers is a name or an address
    find_server_address_or_name "$SERVER"
    local status=$?
    if [ "$status" = "$RESTART_ONCE" ]; then
        console "Restarting once ($NAME) ..."
        initialize && find_server_address_or_name "$NAME"
    elif [ "$status" = "$FAILURE" ]; then
        console err "Unable to unlock $SERVER..."
        console err "Try these steps:"
        console err " 1) Please review your command line input"
        console err " 2) Run \"unlocker list\" and double check if the server is listed"
        console err " 3) If you consider this to be an error or a bug, please report at $HOMEPAGE"
        close $ERROR_BAD_ARGUMENTS
    fi

    return $SUCCESS
}

# save service scheme
SCHEME=$1

# save server address
SERVER=$2

# try to unlock server
bootstrap && unlock_server $@

# cleanup
cleanup
