# Forward standalone MEC builds to the shared dependency graph.
include modules.mk
PROTOS = $(MEC_PROTOS)
CRYPTOS = $(MEC_CRYPTOS)

mec_goal_all = subdirs
mec_goal_install = install-mec
mec_goal_clean = clean-mec
mec_goal_veryclean = clean-mec

.DEFAULT_GOAL := all
.PHONY: all install clean veryclean $(PROTOS) $(CRYPTOS) forward
all install clean veryclean $(PROTOS) $(CRYPTOS): forward

forward:
	$(MAKE) -C .. $(foreach goal,$(or $(MAKECMDGOALS),all),$(or $(mec_goal_$(goal)),mec/$(goal))) \
		MEC_PROTOS="$(PROTOS)" MEC_CRYPTOS="$(CRYPTOS)"
