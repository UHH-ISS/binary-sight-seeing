SET pin_path=../pin
SET make_path=make.exe

pushd "%~dp0"

%make_path% TARGET=ia32 PIN_ROOT=%pin_path%
:: %make_path% DEBUG=1 TARGET=ia32 PIN_ROOT=%pin_path%

popd