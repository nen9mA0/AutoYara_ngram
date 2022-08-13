TARGET_FOLDER = I:/Project/auto_yara/ngram/test
DUMP_FOLDER = I:/Project/auto_yara/ngram/test

SRC = $(wildcard $(TARGET_FOLDER)/*.exe)
TMP = $(subst $(TARGET_FOLDER), $(DUMP_FOLDER), $(SRC))
DST = $(subst .exe,.asmdump,$(TMP))

all: $(DST)

init:
	python rename.py -i $(TARGET_FOLDER)

build_table:
	python load.py -i $(DUMP_FOLDER) -d $(DUMP_FOLDER)/database.pkl

debug:
	@echo $(SRC)
	@echo $(DST)

$(DUMP_FOLDER)/%.asmdump:$(TARGET_FOLDER)/%.exe
	python extractor.py -i "$<" -o "$@"

