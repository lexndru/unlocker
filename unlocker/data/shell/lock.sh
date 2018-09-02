# define exit errors constants
SUCCESS=0
FAILURE=1
ERROR_BAD_CALL=100
ERROR_MISSING_DEPS=101
ERROR_EMPTY_FILE=102
ERROR_JUNK_FILE=103
ERROR_NO_SECRETS=104
ERROR_CANNOT_ENCRYPT=105
ERROR_RACE_COND=110

# set highest debug level available
if [ "x$DEBUG" = "xtrue" ]; then
    set -x -v
fi

# check if the HOME variable is missing
if [ -z "$HOME" ]; then
    echo "Cannot find your user's home directory..." && exit 1
fi

# set path to secrets
SECRETS="$HOME/.unlocker/.secrets"

# set path to encrypted secrets (same directory, different filename)
LOCKED_SECRETS="$SECRETS.lock"

# clean close with error code
close() {
    local EXIT_CODE=0
    if [ $# -eq 1 ]; then
        EXIT_CODE=$1
    fi
    echo "Closing now..." && exit $EXIT_CODE
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

# lock secrets if not already locked
lock_secrets() {
    if file_exists "$LOCKED_SECRETS"; then
        local size=$(ls -lh "$LOCKED_SECRETS" 2> /dev/null | cut -d " " -f5)
        if [ -z "$size" ]; then
            echo "Something very wrong just happend..."
            echo "A moment ago the secrets.lock was on the system and now it's gone"
            echo "Aborting..."
            close $ERROR_RACE_COND
        fi
        if [ "$size" = "0" ]; then
            echo "Warning: an empty secrets.lock is found on the system"
            echo "Warning: it should be removed before the encryption starts"
            while true; do
                read -p "Remove it? [Yn] " answer
                if [ "x$answer" = "xy" -o "x$answer" = "x" ]; then
                    echo "Removing empty secrets.lock file..."
                    rm -f $LOCKED_SECRETS
                    if [ "$?" = "0" ]; then
                        echo "Successfully removed junk file..."
                        break
                    else
                        echo "Failed to remove junk file..."
                        echo "Please manually remove $LOCKED_SECRETS and try again"
                        echo "Size of file is: $size"
                        close $ERROR_JUNK_FILE
                    fi
                elif [ "x$answer" = "xn" ]; then
                    echo "Leaving the file alone ..."
                    echo "Preparing to close because there's nothing to do on an empty file"
                    close $ERROR_EMPTY_FILE
                else
                    echo "Cannot understand answer. Please use \"y\" for yes and \"n\" for no"
                fi
            done
        else
            echo "Secrets are already encrypted (filesize is $size)"
            echo "Use unlock to decrypt secrets..."
            echo "Bye"
            close $SUCCESS
        fi
    fi
    echo "Preparing to encrypt secrets..."
    if ! file_exists "$SECRETS"; then
        echo "Error: cannot find secrets on this system! Aborting..."
        close $ERROR_NO_SECRETS
    fi
    gpg -o "$LOCKED_SECRETS" --symmetric --cipher-algo AES256 "$SECRETS"
    if [ "$?" != "0" ]; then
        echo "Error: failed to encrypt secrets..."
        echo "Error: please correct the errors above and try again"
        close $ERROR_CANNOT_ENCRYPT
    fi
    rm -f "$SECRETS"
    if [ "$?" = "0" ]; then
        echo "Secrets are now encrypted. Don't forget the password!"
    else
        echo "Secrets are now encrypted, but the old unencrypted secrets are still on disk"
        echo "Cannot remove old secrets from: $SECRETS. It's recommended to delete this file"
        echo "You can recover it by decrypting $LOCKED_SECRETS (try \"unlock help\")"
    fi
}

# display this message with the unlocker logo if "help" is asked
if [ "x$1" = "xhelp" ]; then
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
    echo "Lock is one of the two helper scripts part of Unlocker."
    echo "The purpose is to encrypt (lock) secrets with GPG. Write down on a piece of"
    echo "paper the password you'll be using, otherwise there's little chances to"
    echo "recover it."
    exit 0
fi

# check if system has required dependencies to continue
if ! is_installed gpg; then
    echo "Stopping..."
    echo "Cannot encrypt secrets because some dependencies are missing:"
    echo "\"gpg\" is NOT installed! Please install \"gpg\" and try again"
    close $ERROR_MISSING_DEPS
fi

# encryption
lock_secrets
