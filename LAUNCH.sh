#!/bin/bash

GREEN="\\033[1;32m"
DEFAULT="\\033[0;39m"
RED="\\033[1;31m"
ROSE="\\033[1;35m"
BLUE="\\033[1;34m"
WHITE="\\033[0;02m"
YELLOW="\\033[1;33m"
CYAN="\\033[1;36m"

. ./PSSHENV/bin/activate

isredis=`screen -ls | egrep '[0-9]+.Redis_PSSH' | cut -d. -f1`
isserver=`screen -ls | egrep '[0-9]+.Server_PSSH' | cut -d. -f1`

function helptext {
    echo -e $YELLOW"

    "$DEFAULT"
    This script launch:    (Inside screen Daemons)"$CYAN"
      - All Redis in memory servers.
      - Flask server.

    Usage:    LAUNCH.sh
                  [-l | --launchAuto]
                  [-k | --killAll]
                  [-h | --help]
    "
}

function launching_redis {
    conf_dir="${PSSH_HOME}/configs/"
    redis_dir="${PSSH_HOME}/redis/src/"

    screen -dmS "Redis_PSSH"
    sleep 0.1
    echo -e $GREEN"\t* Launching PSSH Redis Servers"$DEFAULT
    screen -S "Redis_PSSH" -X screen -t "7301" bash -c $redis_dir'redis-server '$conf_dir'7301.conf ; read x'
    sleep 0.1
}

function shutting_down_redis {
    redis_dir=${PSSH_HOME}/redis/src/
    bash -c $redis_dir'redis-cli -p 7301 SHUTDOWN'
    sleep 0.1
}

function checking_redis {
    flag_redis=0
    redis_dir=${PSSH_HOME}/redis/src/
    bash -c $redis_dir'redis-cli -p 7301 PING | grep "PONG" &> /dev/null'
    if [ ! $? == 0 ]; then
       echo -e $RED"\t6379 not ready"$DEFAULT
       flag_redis=1
    fi
    sleep 0.1

    return $flag_redis;
}

function launch_redis {
    if [[ ! $isredis ]]; then
        launching_redis;
    else
        echo -e $RED"\t* A D4_Redis screen is already launched"$DEFAULT
    fi
}

function launching_server {
    screen -dmS "Server_PSSH"
    sleep 0.1
    echo -e $GREEN"\t* Launching PSSH server"$DEFAULT

    # LAUNCH CORE MODULE
    screen -S "Server_PSSH" -X screen -t "server" bash -c "cd ${PSSH_HOME}/bin; ./passive_ssh_server.py; read x"
    sleep 0.1
}

function launch_server {
    if [[ ! $isserver ]]; then
        launching_server;
    else
        echo -e $RED"\t* A Server_PSSH screen is already launched"$DEFAULT
    fi
}

function killall {


    if [[ $isredis || $isgflask ]]; then
        echo -e $GREEN"\t* Gracefully closing PSSH ..."$DEFAULT
        kill $isserver
        echo -e $GREEN"\t* $isserver killed."$DEFAULT
        echo -e $GREEN"\t* Gracefully closing redis servers ..."$DEFAULT
        shutting_down_redis;
        kill $isredis
        sleep 0.2
    else
        echo -e $RED"\t* No screen to kill"$DEFAULT
    fi
}

function launch_all {
    helptext;
    launch_redis;
    launch_server;
}

#If no params, display the menu
[[ $@ ]] || {

    helptext;

    options=("Redis" "Killall")

    menu() {
        echo "What do you want to Launch?:"
        for i in ${!options[@]}; do
            printf "%3d%s) %s\n" $((i+1)) "${choices[i]:- }" "${options[i]}"
        done
        [[ "$msg" ]] && echo "$msg"; :
    }

    prompt="Check an option (again to uncheck, ENTER when done): "
    while menu && read -rp "$prompt" numinput && [[ "$numinput" ]]; do
        for num in $numinput; do
            [[ "$num" != *[![:digit:]]* ]] && (( num > 0 && num <= ${#options[@]} )) || {
                msg="Invalid option: $num"; break
            }
            ((num--)); msg="${options[num]} was ${choices[num]:+un}checked"
            [[ "${choices[num]}" ]] && choices[num]="" || choices[num]="+"
        done
    done

    for i in ${!options[@]}; do
        if [[ "${choices[i]}" ]]; then
            case ${options[i]} in
                Redis)
                    launch_redis;
                    ;;
                Killall)
                    killall;
                    ;;
            esac
        fi
    done

    exit
}

while [ "$1" != "" ]; do
    case $1 in
        -l | --launchAuto )         launch_all;
                                    ;;
        -k | --killAll )            helptext;
                                    killall;
                                    ;;
        -h | --help )               helptext;
                                    exit
                                    ;;
        * )                         helptext
                                    exit 1
    esac
    shift
done
