TARGET_FOLDER = I:/Project/auto_yara/ngram/test
DUMP_FOLDER = K:/asmdump

SRC = $(wildcard $(TARGET_FOLDER)/*.exe)
TMP = $(subst $(TARGET_FOLDER), $(DUMP_FOLDER), $(SRC))
DST = $(subst .exe,.asmdump,$(TMP))

all: $(DST)

init:
	python rename.py -i $(TARGET_FOLDER)

debug:
	@echo $(SRC)
	@echo $(DST)

$(DUMP_FOLDER)/%.asmdump:$(TARGET_FOLDER)/%.exe
	python extractor.py -i "$<"" -o "$@"