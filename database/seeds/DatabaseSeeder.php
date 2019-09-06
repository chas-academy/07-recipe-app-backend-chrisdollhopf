<?php

use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     *
     * @return void
     */
    public function run()
    {
        Eloquent::ungauard();
        $this->call('UserTableSeeder');
        $this->command->info('User table seeded');
        $this->call('RecipeListsTableSeeder');
        $this->command('RecipeList table seeded.');
    }
}
