#include "tbf.h"

int tbf_rl(tbf * rl)
{
	time_t now = time(NULL);
	time_t delta = now - rl->timestamp;
	if ((0 <= delta) && (delta < rl->burst))
	{
		rl->count++;
	}
	else
	{
		if (rl->mark)
		{
			//printf("%d count of  suppressed actions\n", rl->mark);
			rl->mark = 0;
		}
		rl->timestamp = now;
		rl->count = 0;
		return 1;
	}

	if (rl->count >= rl->rate)
	{
		rl->mark++;
		return 0;
	}
	return 0;
}
