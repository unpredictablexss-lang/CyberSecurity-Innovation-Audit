void test(void) {
    printf(("\n"
            "Options:\n"
            "--mode=<accel|motion|delta|sequence>\n"
            "    accel    print accel factor (default)\n"
            "    motion   print motion to accelerated motion\n"
            "    delta    print delta to accelerated delta\n"
            "    sequence print motion for custom delta sequence\n"
            "--maxdx=<double> stop increasing dx at maxdx\n"
            "--steps=<double> increase dx by step each round\n"
            "--custom-points=\"<double>;...;<double>\" define a custom function\n"
            "starting from 0. defaults to 1.0\n"));
}
