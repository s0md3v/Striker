import time
keep_running = True

class animate:
	def __init__(self, frames, time):
		self.frames = frames
	def stop():
		keep_running = False
	def printer(frames, allowed=keep_running):
		while allowed:
			for each_frame in frames:
				time.sleep(0.3)
				print (each_frame, end='\r')

fleet = ['.      ', ' .      ', '  .       ', '   .      ', '    .     ', '      .'
]

animate.printer(fleet)
