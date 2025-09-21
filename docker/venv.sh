
cd $HOME

/usr/bin/python3.12 -m venv --copies --upgrade-deps .venv
source .venv/bin/activate
    if [ -f "$HOME/tmp/requirements.txt" ]; then
        pip install -r $HOME/tmp/requirements.txt
    fi

    if [ -d "$HOME/tmp/venv" ]; then
        cp -r $HOME/tmp/venv/* $HOME/
        chown $USER:0 -R $HOME/
        chmod 750 -R $HOME/
        #cd $HOME
        #python3 manage.py collectstatic --no-input
    fi
    ##Removal of pip
    pip uninstall -y pip
deactivate