all: format

format:
	dart format --fix lib

clean:
	git clean -fdx -e .vscode

analyze:
	dart pub global list | grep pana || dart pub global activate pana
	dart pub global run pana --no-warning

publish: format clean
	test -z "$(shell git status --porcelain)"
	dart pub publish -n
	# git tag $(shell grep version pubspec.yaml | sed 's/version\s*:\s*/v/g')

.PHONY: format clean publish analyze
