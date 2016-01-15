set -e

if [ ! -e capstone ]; then
  git clone https://github.com/aquynh/capstone
fi

(
  cd capstone
  ./make.sh
  sudo ./make.sh install
  cd bindings/python
  make
  sudo make install3
)

echo ""
echo "Auto-register the command: echo 'source $PWD/flow.py' >> ~/.gdbinit"
