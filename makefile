PYTHON = python

TARGET_FOLDER = I:/Project/auto_yara/ngram/test
DUMP_FOLDER = I:/Project/auto_yara/ngram/test

SRC = $(wildcard $(TARGET_FOLDER)/*.exe)
TMP = $(subst $(TARGET_FOLDER), $(DUMP_FOLDER), $(SRC))
DST = $(subst .exe,.asmdump,$(TMP))

all: $(DST)

init:
	$(PYTHON) rename.py -i $(TARGET_FOLDER)

build_table:
	$(PYTHON) load.py -i $(DUMP_FOLDER) -d $(DUMP_FOLDER)/database.pkl -n 4 -a x86

debug:
	@echo $(SRC)
	@echo $(DST)

$(DUMP_FOLDER)/%.asmdump:$(TARGET_FOLDER)/%.exe
	$(PYTHON) extractor.py -i "$<" -o "$@"

