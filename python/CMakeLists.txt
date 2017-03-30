# Provisioning Python compilation and installation

execute_process(COMMAND python -c "from distutils.sysconfig import get_python_lib; print get_python_lib()"
		OUTPUT_VARIABLE PYTHON_SITE_PACKAGES
		OUTPUT_STRIP_TRAILING_WHITESPACE)

# Compile the modules?  It only speeds up module loading, not runtime...
# python -c 'import py_compile; py_compile.compile ("MODULE.py")'
# python -c 'import compileall; compileall.compile_dir (".")'
# add_custom_command (makebe COMMAND ...)
# add_custom_target (newbe DEPENDS makebe)

configure_file (setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/setup.py @ONLY)

add_custom_command (OUTPUT lillydap-shared-module-build
			COMMAND python ${CMAKE_CURRENT_BINARY_DIR}/setup.py build
			COMMAND python ${CMAKE_CURRENT_BINARY_DIR}/setup.py install --root ${CMAKE_CURRENT_BINARY_DIR}/lillydap --install-platlib .
			DEPENDS opsize.h
	)
add_custom_target (lillydap-shared-module ALL
		DEPENDS lillydap-shared-module-build)
add_custom_command (TARGET lillydap-shared-module
	POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/lillydap.py ${CMAKE_CURRENT_BINARY_DIR}/lillydap/__init__.py
	)

add_custom_command (OUTPUT opsize.h
			COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/make_opsize_h.sh ${CMAKE_SOURCE_DIR}/lib/msgop.tab ${CMAKE_CURRENT_BINARY_DIR}/opsize.h )

#OLD# install(FILES _quickder.so DESTINATION ${PYTHON_SITE_PACKAGES}/quick_der)

#SEECOPYABOVE# install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/lillydap.py DESTINATION ${PYTHON_SITE_PACKAGES}/lillydap/__init__.py)
# install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/__init__.py DESTINATION ${PYTHON_SITE_PACKAGES}/lillydap)
install(CODE "execute_process(COMMAND ${CMAKE_CURRENT_BINARY_DIR}/setup.py install)")
