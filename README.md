# IDEK2022 CTF Write Up

Original write-ups by :raccoon::ninja: on [IDEK2022-CTF](https://ctf.idek.team).

This is my first time playing in a team ([B6A](https://b6a.black)) and I'm so honoured to have this opportunity. They are very nice and supportive and most importantly, they are **really strong**. I'm overjoyed that I can contribute and it was a very fun experience.

### Solved challenges that I took some part:
- Web: Simple File Server (most of the work), JSON Beautifier (initial research)
- OSINT: NMPZ (researched and guessed the less obvious countries), Crime Confusion (everyone solved it together, this is fun)
- Forensic: Hidden Gem 1 (minor role, double check missed info)
- Misc: Welcome, Survey (I think I submitted the flags, won't be writing write-up for these), NIKI (translation, testing and programming?)

## Reflections

I was shocked by the difficulty of this CTF, considering last year's difficulty.
Most challenges except OSINT are 3.5~4.5/5 in terms of difficulty.
Even I had looked at the past problems it didn't help much, and this is the first time that I couldn't solve any crypto challenge (on the other hand our team has really strong crypto people)

Still I really enjoyed Simple File Server (1.5/5: file inclusion and session forgery) and researching on JSON Beautifier (3.5/5: eval with string context bypass with DOM clobbering + XSS with CSP restriction). I also learnt much in Geoguessing.

Specifics:
- I was too lazy to do research on DOM clobbering vectors and couldn't really assemble the different pieces
- I didn't embrace logical bruteforcing for NIKI quick enough.
- I don't know the inner workings of GO.
- I could have sticked around at PayWall longer.

## Declaration

- All tools deployed were solely for learning cybersecurity.
- The tools were not used against any machine other than those provided by the organizer.
- Skills covered here are not to be used in any illegal activity and I do not endorse any illegal activity.
